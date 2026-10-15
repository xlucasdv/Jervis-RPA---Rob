"""Cadastro de clientes, serviços e vínculos (customers, service, customer_services).

As funções recebem uma conexão aberta (``jervis.db.connect``) e não fazem commit: quem chama decide.
A chave MFA entra e sai já criptografada; descriptografar é responsabilidade de quem vai usá-la
(``jervis.db.crypto``), e nada aqui a exibe.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import pymysql

from jervis.errors import JervisError

_DUPLICATE = 1062  # ER_DUP_ENTRY
_ROW_IS_REFERENCED = 1451  # ER_ROW_IS_REFERENCED_2 (chave estrangeira)


class RecordError(JervisError):
    """Cadastro inexistente, duplicado ou ambíguo."""


@dataclass
class Customer:
    id: int
    name: str
    desk_manager_id: str | None
    services: list[str] = field(default_factory=list)  # slugs vinculados
    with_mfa: list[str] = field(default_factory=list)  # slugs com chave MFA própria do cliente
    external: dict[str, str] = field(default_factory=dict)  # slug → nome do cliente na plataforma (se cadastrado)
    contracts: dict[str, dict[str, Any]] = field(default_factory=dict)  # slug → {"produtos": [...], "dispositivos": N}
    active: bool = True  # inativo (POC, trial, cadastro antigo): fora do fechamento mensal e do --all
    inactive_reason: str | None = None

    def name_on(self, slug: str) -> str:
        """Nome usado para achar o cliente na plataforma: o do vínculo ou, sem ele, o do cadastro."""
        return self.external.get(slug) or self.name


@dataclass
class Service:
    id: int
    slug: str
    url: str
    class_identifier: str
    settings: dict[str, Any]
    customers: int = 0  # clientes vinculados
    has_mfa: bool = False  # chave MFA da conta de parceiro cadastrada


# --- clientes ---------------------------------------------------------------------


def add_customer(conn, name: str, desk_manager_id: str | None) -> int:
    name = (name or "").strip()
    if not name:
        raise RecordError("Informe o nome do cliente.")
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO customers (name, desk_manager_id) VALUES (%s, %s)", (name, _blank_to_none(desk_manager_id)))
            return cur.lastrowid
    except pymysql.err.IntegrityError as exc:
        if exc.args and exc.args[0] == _DUPLICATE:
            raise RecordError(f"Já existe um cliente com o id do Desk Manager '{desk_manager_id}'.") from exc
        raise


def update_customer(conn, ref: str, name: str | None = None, desk_manager_id: str | None = None) -> Customer:
    customer = find_customer(conn, ref)
    changes: dict[str, Any] = {}
    if name is not None:
        if not name.strip():
            raise RecordError("O nome do cliente não pode ficar vazio.")
        changes["name"] = name.strip()
    if desk_manager_id is not None:
        changes["desk_manager_id"] = _blank_to_none(desk_manager_id)
    if changes:
        sets = ", ".join(f"{column} = %s" for column in changes)
        try:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE customers SET {sets} WHERE id = %s", (*changes.values(), customer.id))
        except pymysql.err.IntegrityError as exc:
            if exc.args and exc.args[0] == _DUPLICATE:
                raise RecordError(f"Já existe um cliente com o id do Desk Manager '{desk_manager_id}'.") from exc
            raise
    return find_customer(conn, str(customer.id))


def list_customers(conn) -> list[Customer]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT c.id, c.name, c.desk_manager_id, c.active, c.inactive_reason, s.slug, cs.mfa_secret_encrypted IS NOT NULL, "
            "cs.external_name, cs.products, cs.contracted_devices "
            "FROM customers c LEFT JOIN customer_services cs ON cs.customer_id = c.id "
            "LEFT JOIN service s ON s.id = cs.service_id ORDER BY c.name, c.id, s.slug"
        )
        customers: dict[int, Customer] = {}
        for cid, name, dm, active, reason, slug, has_mfa, external, products, contracted in cur.fetchall():
            customer = customers.setdefault(cid, Customer(cid, name, dm, active=bool(active), inactive_reason=reason))
            if slug:
                _add_link(customer, slug, has_mfa, external, products, contracted)
        return list(customers.values())


def find_customer(conn, ref: str) -> Customer:
    """Cliente pelo id numérico, pelo id do Desk Manager ou pelo nome (sem diferenciar maiúsculas)."""
    ref = (ref or "").strip()
    columns = "SELECT id, name, desk_manager_id, active, inactive_reason FROM customers"
    with conn.cursor() as cur:
        if ref.isdigit():
            cur.execute(f"{columns} WHERE id = %s", (int(ref),))
            rows = cur.fetchall()
            if rows:
                return _with_links(conn, _customer(rows[0]))
        cur.execute(f"{columns} WHERE desk_manager_id = %s", (ref,))
        rows = cur.fetchall()
        if not rows:
            cur.execute(f"{columns} WHERE LOWER(name) = LOWER(%s) ORDER BY id", (ref,))
            rows = cur.fetchall()
    if not rows:
        raise RecordError(f"Cliente '{ref}' não encontrado. Veja os cadastrados com 'jervis customers list'.")
    if len(rows) > 1:
        options = "; ".join(f"id {r[0]} (Desk Manager: {r[2] or '—'})" for r in rows)
        raise RecordError(f"Há {len(rows)} clientes chamados '{ref}': {options}. Use o id.")
    return _with_links(conn, _customer(rows[0]))


def _customer(row) -> Customer:
    cid, name, dm, active, reason = row
    return Customer(cid, name, dm, active=bool(active), inactive_reason=reason)


def set_active(conn, ref: str, active: bool, reason: str | None = None) -> Customer:
    """Ativa ou inativa o cliente (inativo: fora do fechamento mensal e do relatório de todos)."""
    customer = find_customer(conn, ref)
    with conn.cursor() as cur:
        cur.execute("UPDATE customers SET active = %s, inactive_reason = %s WHERE id = %s",
                    (1 if active else 0, None if active else _blank_to_none(reason), customer.id))
    return find_customer(conn, str(customer.id))


def merge_customers(conn, source_ref: str, target_ref: str) -> tuple[Customer, Customer, list[str]]:
    """Junta dois cadastros do mesmo cliente: os vínculos e o histórico de relatórios de ``source`` passam para
    ``target`` e ``source`` é apagado. Cada vínculo mantém o nome do cliente na plataforma (o nome do cadastro de
    origem vira o nome na plataforma quando não havia um). Recusa se os dois têm o mesmo serviço. Não faz commit."""
    source, target = find_customer(conn, source_ref), find_customer(conn, target_ref)
    if source.id == target.id:
        raise RecordError("Origem e destino são o mesmo cliente.")
    both = sorted(set(source.services) & set(target.services))
    if both:
        raise RecordError(f"'{source.name}' e '{target.name}' estão vinculados ao mesmo serviço ({', '.join(both)}): um cliente "
                          "tem um vínculo por serviço. Desative o cadastro que sobra ('jervis customers deactivate').")
    with conn.cursor() as cur:
        cur.execute("UPDATE customer_services SET customer_id = %s, external_name = COALESCE(external_name, %s) "
                    "WHERE customer_id = %s", (target.id, source.name, source.id))
        cur.execute("UPDATE customer_reports SET customer_id = %s WHERE customer_id = %s", (target.id, source.id))
        if source.desk_manager_id and not target.desk_manager_id:  # único: libera na origem antes de levar
            cur.execute("UPDATE customers SET desk_manager_id = NULL WHERE id = %s", (source.id,))
            cur.execute("UPDATE customers SET desk_manager_id = %s WHERE id = %s", (source.desk_manager_id, target.id))
        cur.execute("DELETE FROM customers WHERE id = %s", (source.id,))
    return source, find_customer(conn, str(target.id)), source.services


def remove_customer(conn, ref: str) -> Customer:
    customer = find_customer(conn, ref)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM customers WHERE id = %s", (customer.id,))  # vínculos saem em cascata
    return customer


def _with_links(conn, customer: Customer) -> Customer:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT s.slug, cs.mfa_secret_encrypted IS NOT NULL, cs.external_name, cs.products, cs.contracted_devices "
            "FROM customer_services cs JOIN service s ON s.id = cs.service_id WHERE cs.customer_id = %s ORDER BY s.slug",
            (customer.id,))
        for slug, has_mfa, external, products, contracted in cur.fetchall():
            _add_link(customer, slug, has_mfa, external, products, contracted)
    return customer


def _add_link(customer: Customer, slug: str, has_mfa, external: str | None, products: str | None = None,
              contracted: int | None = None) -> None:
    customer.services.append(slug)
    if has_mfa:
        customer.with_mfa.append(slug)
    if external:
        customer.external[slug] = external
    if products or contracted is not None:
        customer.contracts[slug] = {"produtos": [p.strip() for p in (products or "").split(";") if p.strip()],
                                    "dispositivos": contracted}


# --- serviços ---------------------------------------------------------------------


def add_service(conn, slug: str, url: str, class_identifier: str, settings: dict[str, Any] | None = None) -> int:
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO service (slug, url, class_identifier, settings) VALUES (%s, %s, %s, %s)",
                        (slug, url, class_identifier, json.dumps(settings or {}, ensure_ascii=False)))
            return cur.lastrowid
    except pymysql.err.IntegrityError as exc:
        if exc.args and exc.args[0] == _DUPLICATE:
            raise RecordError(f"Já existe um serviço com o slug '{slug}'. Use 'jervis services update'.") from exc
        raise


def update_service(conn, slug: str, url: str | None = None, class_identifier: str | None = None,
                   settings: dict[str, Any] | None = None, unset: list[str] | None = None) -> Service:
    service = find_service(conn, slug)
    merged = {**service.settings, **(settings or {})}
    for key in unset or []:
        merged.pop(key, None)
    with conn.cursor() as cur:
        cur.execute("UPDATE service SET url = %s, class_identifier = %s, settings = %s WHERE id = %s",
                    (url or service.url, class_identifier or service.class_identifier,
                     json.dumps(merged, ensure_ascii=False), service.id))
    return find_service(conn, slug)


def list_services(conn) -> list[Service]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT s.id, s.slug, s.url, s.class_identifier, s.settings, COUNT(cs.id), s.mfa_secret_encrypted IS NOT NULL "
            "FROM service s LEFT JOIN customer_services cs ON cs.service_id = s.id GROUP BY s.id ORDER BY s.slug")
        return [Service(i, slug, url, cls, _json(settings), n, bool(mfa)) for i, slug, url, cls, settings, n, mfa in cur.fetchall()]


def find_service(conn, slug: str) -> Service:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT s.id, s.slug, s.url, s.class_identifier, s.settings, COUNT(cs.id), s.mfa_secret_encrypted IS NOT NULL "
            "FROM service s LEFT JOIN customer_services cs ON cs.service_id = s.id WHERE s.slug = %s GROUP BY s.id", (slug,))
        row = cur.fetchone()
    if not row:
        raise RecordError(f"Serviço '{slug}' não encontrado. Veja os cadastrados com 'jervis services list'.")
    i, slug, url, cls, settings, n, mfa = row
    return Service(i, slug, url, cls, _json(settings), n, bool(mfa))


def set_service_mfa(conn, slug: str, mfa_encrypted: str | None) -> Service:
    """Chave MFA da conta de parceiro (token criptografado; None apaga)."""
    service = find_service(conn, slug)
    with conn.cursor() as cur:
        cur.execute("UPDATE service SET mfa_secret_encrypted = %s WHERE id = %s", (mfa_encrypted, service.id))
    return find_service(conn, slug)


def remove_service(conn, slug: str) -> Service:
    service = find_service(conn, slug)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM service WHERE id = %s", (service.id,))
    except pymysql.err.IntegrityError as exc:
        if exc.args and exc.args[0] == _ROW_IS_REFERENCED:
            raise RecordError(f"O serviço '{slug}' está vinculado a {service.customers} cliente(s). "
                              "Desvincule-os antes (jervis customers unlink).") from exc
        raise
    return service


# --- vínculos ---------------------------------------------------------------------

KEEP = object()


def link(conn, customer_ref: str, slug: str, mfa_encrypted: Any = KEEP, external_name: Any = KEEP,
         products: Any = KEEP, contracted_devices: Any = KEEP) -> tuple[Customer, Service, bool]:
    """Vincula cliente e serviço (ou atualiza o vínculo). Para ``mfa_encrypted`` e ``external_name``:
    um valor grava, None (ou texto vazio) apaga, omitido mantém o atual. Devolve (cliente, serviço, criado)."""
    customer, service = find_customer(conn, customer_ref), find_service(conn, slug)
    if external_name is not KEEP:
        external_name = _blank_to_none(external_name)
    if products is not KEEP:
        products = _blank_to_none(products)
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM customer_services WHERE customer_id = %s AND service_id = %s", (customer.id, service.id))
        row = cur.fetchone()
        if row is None:
            values = {"external_name": external_name, "mfa_secret_encrypted": mfa_encrypted, "products": products,
                      "contracted_devices": contracted_devices}
            values = {k: (None if v is KEEP else v) for k, v in values.items()}
            cur.execute(
                "INSERT INTO customer_services (customer_id, service_id, external_name, mfa_secret_encrypted, products, "
                "contracted_devices) VALUES (%s, %s, %s, %s, %s, %s)",
                (customer.id, service.id, values["external_name"], values["mfa_secret_encrypted"], values["products"],
                 values["contracted_devices"]))
            return find_customer(conn, str(customer.id)), service, True
        changes = {column: value for column, value in (("mfa_secret_encrypted", mfa_encrypted), ("external_name", external_name),
                                                       ("products", products), ("contracted_devices", contracted_devices))
                   if value is not KEEP}
        if changes:
            sets = ", ".join(f"{column} = %s" for column in changes)
            cur.execute(f"UPDATE customer_services SET {sets} WHERE id = %s", (*changes.values(), row[0]))
    return find_customer(conn, str(customer.id)), service, False


def unlink(conn, customer_ref: str, slug: str) -> tuple[Customer, Service]:
    customer, service = find_customer(conn, customer_ref), find_service(conn, slug)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM customer_services WHERE customer_id = %s AND service_id = %s", (customer.id, service.id))
        if cur.rowcount == 0:
            raise RecordError(f"O cliente '{customer.name}' não está vinculado ao serviço '{slug}'.")
    return customer, service


def mfa_token(conn, customer_ref: str, slug: str) -> str | None:
    """Chave MFA criptografada que vale para o vínculo: a própria do cliente, se houver; senão, a da conta de
    parceiro do serviço. Descriptografe com jervis.db.crypto só na hora do uso."""
    customer, service = find_customer(conn, customer_ref), find_service(conn, slug)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cs.mfa_secret_encrypted, s.mfa_secret_encrypted FROM customer_services cs "
            "JOIN service s ON s.id = cs.service_id WHERE cs.customer_id = %s AND cs.service_id = %s",
            (customer.id, service.id))
        row = cur.fetchone()
    if row is None:
        raise RecordError(f"O cliente '{customer.name}' não está vinculado ao serviço '{slug}'.")
    return row[0] or row[1]


# --- relatórios gerados e revisão -------------------------------------------------------

REVIEW_STATUSES = ("pendente", "aprovado", "rejeitado", "substituido", "falha")


@dataclass
class CustomerReport:
    id: int
    customer_id: int
    customer: str
    competencia: str | None
    periodo: str
    run_dir: str | None
    resultado: str
    status: str
    origem: str
    gerado_por: str | None
    gerado_em: Any
    revisado_por: str | None = None
    revisado_em: Any = None
    observacao: str | None = None


_REPORT_COLUMNS = ("r.id, r.customer_id, c.name, r.competencia, r.periodo, r.run_dir, r.resultado, r.status, r.origem, "
                   "r.gerado_por, r.created_at, r.revisado_por, r.revisado_em, r.observacao")


def record_report(conn, customer_id: int, competencia: str | None, periodo: str, run_dir: str | None, resultado: str,
                  origem: str, gerado_por: str | None, observacao: str | None = None) -> int:
    """Registra um relatório gerado: pendente de revisão (ou "falha", se nada foi coletado). O pendente anterior do
    mesmo cliente e competência vira "substituido": só a geração mais recente é revisada."""
    status = "falha" if resultado == "falha" else "pendente"  # nada coletado: não há o que revisar
    with conn.cursor() as cur:
        if status == "pendente":
            cur.execute("UPDATE customer_reports SET status = 'substituido' WHERE customer_id = %s AND status = 'pendente' "
                        "AND competencia <=> %s", (customer_id, competencia))
        cur.execute("INSERT INTO customer_reports (customer_id, competencia, periodo, run_dir, resultado, status, origem, "
                    "gerado_por, observacao) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (customer_id, competencia, periodo[:64], run_dir, resultado, status, origem[:64], gerado_por,
                     (observacao or None) and observacao[:1024]))
        return cur.lastrowid


def list_reports(conn, status: str | None = "pendente", competencia: str | None = None) -> list[CustomerReport]:
    where, params = [], []
    if status:
        where.append("r.status = %s")
        params.append(status)
    if competencia:
        where.append("r.competencia = %s")
        params.append(competencia)
    sql = (f"SELECT {_REPORT_COLUMNS} FROM customer_reports r JOIN customers c ON c.id = r.customer_id"
           + (f" WHERE {' AND '.join(where)}" if where else "") + " ORDER BY r.competencia DESC, c.name, r.id DESC")
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return [CustomerReport(*row) for row in cur.fetchall()]


def find_report(conn, ref: str, competencia: str | None = None) -> CustomerReport:
    """Relatório pelo id (número) ou o pendente mais recente do cliente (id, id do Desk Manager ou nome)."""
    ref = (ref or "").strip()
    with conn.cursor() as cur:
        if ref.startswith("#") and ref[1:].isdigit():
            cur.execute(f"SELECT {_REPORT_COLUMNS} FROM customer_reports r JOIN customers c ON c.id = r.customer_id "
                        "WHERE r.id = %s", (int(ref[1:]),))
            row = cur.fetchone()
            if not row:
                raise RecordError(f"Relatório {ref} não encontrado. Veja 'jervis reviews list'.")
            return CustomerReport(*row)
    customer = find_customer(conn, ref)
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_REPORT_COLUMNS} FROM customer_reports r JOIN customers c ON c.id = r.customer_id "
                    "WHERE r.customer_id = %s AND r.status = 'pendente'" + (" AND r.competencia = %s" if competencia else "")
                    + " ORDER BY r.id DESC LIMIT 1", (customer.id, competencia) if competencia else (customer.id,))
        row = cur.fetchone()
    if not row:
        raise RecordError(f"Nenhum relatório pendente de revisão para '{customer.name}'"
                          + (f" em {competencia}" if competencia else "") + ". Veja 'jervis reviews list --status todos'.")
    return CustomerReport(*row)


def review_report(conn, report_id: int, status: str, reviewer: str, note: str | None = None) -> None:
    if status not in ("aprovado", "rejeitado"):
        raise ValueError(status)
    with conn.cursor() as cur:
        cur.execute("UPDATE customer_reports SET status = %s, revisado_por = %s, revisado_em = NOW(), "
                    "observacao = COALESCE(%s, observacao) WHERE id = %s AND status = 'pendente'",
                    (status, reviewer, (note or None) and note[:1024], report_id))
        if cur.rowcount == 0:
            raise RecordError(f"O relatório #{report_id} não está pendente de revisão.")


def reopen_report(conn, report_id: int) -> None:
    """Aprovado ou rejeitado volta a pendente (engano na revisão), se ainda for a geração mais recente do cliente."""
    with conn.cursor() as cur:
        cur.execute("SELECT customer_id, competencia, status FROM customer_reports WHERE id = %s", (report_id,))
        row = cur.fetchone()
        if not row:
            raise RecordError(f"Relatório #{report_id} não encontrado.")
        customer_id, competencia, status = row
        if status not in ("aprovado", "rejeitado"):
            raise RecordError(f"O relatório #{report_id} não foi revisado (situação: {status}).")
        cur.execute("SELECT COUNT(*) FROM customer_reports WHERE customer_id = %s AND competencia <=> %s AND id > %s "
                    "AND status <> 'falha'", (customer_id, competencia, report_id))
        if cur.fetchone()[0]:
            raise RecordError("Já existe uma geração mais nova desse relatório; revise a mais recente.")
        cur.execute("UPDATE customer_reports SET status = 'pendente', revisado_por = NULL, revisado_em = NULL WHERE id = %s",
                    (report_id,))


def list_competencias(conn) -> list[str]:
    """Meses (AAAA-MM) com relatórios gerados, do mais recente para o mais antigo."""
    with conn.cursor() as cur:
        cur.execute("SELECT DISTINCT competencia FROM customer_reports WHERE competencia IS NOT NULL ORDER BY competencia DESC")
        return [row[0] for row in cur.fetchall()]


# --- contas da interface web --------------------------------------------------------------

WEB_ROLES = ("leitura", "revisor", "admin")
LOCK_AFTER, LOCK_MINUTES = 5, 15  # tentativas erradas seguidas e minutos de bloqueio


@dataclass
class WebUser:
    id: int
    email: str
    name: str | None
    role: str
    active: bool
    password_hash: str
    must_change_password: bool
    mfa_secret_encrypted: str | None
    mfa_last_step: int | None
    failed_attempts: int
    locked_until: Any
    session_epoch: int
    last_login_at: Any

    @property
    def mfa_configured(self) -> bool:
        return bool(self.mfa_secret_encrypted)


_WEB_USER_COLUMNS = ("id, email, name, role, active, password_hash, must_change_password, mfa_secret_encrypted, "
                     "mfa_last_step, failed_attempts, locked_until, session_epoch, last_login_at")


def _web_user(row) -> WebUser:
    return WebUser(row[0], row[1], row[2], row[3], bool(row[4]), row[5], bool(row[6]), row[7], row[8], row[9] or 0,
                   row[10], row[11] or 0, row[12])


def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 255:
        raise RecordError(f"'{email}' não parece um e-mail (nome@empresa.com.br).")
    return email


def list_web_users(conn) -> list[WebUser]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_WEB_USER_COLUMNS} FROM web_users ORDER BY active DESC, name, email")
        return [_web_user(row) for row in cur.fetchall()]


def find_web_user(conn, email: str) -> WebUser | None:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_WEB_USER_COLUMNS} FROM web_users WHERE email = %s", ((email or "").strip().lower(),))
        row = cur.fetchone()
    return _web_user(row) if row else None


def get_web_user(conn, user_id: int) -> WebUser | None:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_WEB_USER_COLUMNS} FROM web_users WHERE id = %s", (user_id,))
        row = cur.fetchone()
    return _web_user(row) if row else None


def require_web_user(conn, ref: int | str) -> WebUser:
    """Conta pelo id (interface) ou pelo e-mail (terminal)."""
    user = get_web_user(conn, ref) if isinstance(ref, int) else find_web_user(conn, ref)
    if not user:
        raise RecordError(f"Conta '{ref}' não encontrada. Veja 'jervis web users list'.")
    return user


def add_web_user(conn, email: str, name: str | None, role: str, password_hash: str) -> int:
    """Nova conta com senha temporária (troca obrigatória no primeiro login)."""
    email = normalize_email(email)
    if role not in WEB_ROLES:
        raise RecordError(f"Perfil '{role}' inválido. Opções: {', '.join(WEB_ROLES)}.")
    if find_web_user(conn, email):
        raise RecordError(f"Já existe uma conta para {email}.")
    with conn.cursor() as cur:
        cur.execute("INSERT INTO web_users (email, name, role, password_hash, must_change_password) VALUES (%s, %s, %s, %s, 1)",
                    (email, _blank_to_none(name), role, password_hash))
        return cur.lastrowid


def active_admins(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM web_users WHERE role = 'admin' AND active = 1")
        return cur.fetchone()[0]


def update_web_user(conn, ref: int | str, role: str | None = None, active: bool | None = None,
                    name: str | None = None) -> WebUser:
    """Perfil, nome ou situação. Suspender derruba as sessões abertas. Não deixa o Jervis sem admin ativo."""
    user = require_web_user(conn, ref)
    if role is not None and role not in WEB_ROLES:
        raise RecordError(f"Perfil '{role}' inválido. Opções: {', '.join(WEB_ROLES)}.")
    losing_admin = user.role == "admin" and user.active and ((role and role != "admin") or active is False)
    if losing_admin and active_admins(conn) <= 1:
        raise RecordError("Essa é a única conta admin ativa: crie ou promova outro admin antes.")
    with conn.cursor() as cur:
        cur.execute("UPDATE web_users SET role = COALESCE(%s, role), active = COALESCE(%s, active), "
                    "name = COALESCE(%s, name), session_epoch = session_epoch + %s WHERE id = %s",
                    (role, None if active is None else int(active), _blank_to_none(name),
                     1 if active is False or (role and role != user.role) else 0, user.id))
    return get_web_user(conn, user.id)


def set_web_password(conn, user_id: int, password_hash: str, temporary: bool) -> None:
    """Nova senha (temporária, definida pelo admin, ou a escolhida pela pessoa). Desbloqueia a conta e derruba as
    outras sessões."""
    with conn.cursor() as cur:
        cur.execute("UPDATE web_users SET password_hash = %s, must_change_password = %s, password_changed_at = NOW(), "
                    "failed_attempts = 0, locked_until = NULL, session_epoch = session_epoch + 1 WHERE id = %s",
                    (password_hash, int(temporary), user_id))


def set_web_mfa(conn, user_id: int, secret_encrypted: str | None, last_step: int | None = None) -> None:
    """Grava a chave do app autenticador (ou apaga, para configurar de novo no próximo login)."""
    with conn.cursor() as cur:
        cur.execute("UPDATE web_users SET mfa_secret_encrypted = %s, mfa_last_step = %s, "
                    "session_epoch = session_epoch + %s WHERE id = %s",
                    (secret_encrypted, last_step, 0 if secret_encrypted else 1, user_id))


def use_mfa_step(conn, user_id: int, step: int) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE web_users SET mfa_last_step = %s WHERE id = %s", (step, user_id))


def record_web_failure(conn, user_id: int) -> bool:
    """Tentativa errada (senha ou código). Devolve True se a conta acabou de ser bloqueada."""
    with conn.cursor() as cur:
        cur.execute("UPDATE web_users SET failed_attempts = failed_attempts + 1, "
                    "locked_until = IF(failed_attempts >= %s, NOW() + INTERVAL %s MINUTE, locked_until) WHERE id = %s",
                    (LOCK_AFTER, LOCK_MINUTES, user_id))
        cur.execute("SELECT failed_attempts FROM web_users WHERE id = %s", (user_id,))
        return cur.fetchone()[0] == LOCK_AFTER


def record_web_login(conn, user_id: int) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE web_users SET failed_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = %s",
                    (user_id,))


def _blank_to_none(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def _json(value) -> dict[str, Any]:
    if value is None or value == "":
        return {}
    data = json.loads(value) if isinstance(value, (str, bytes)) else value
    return data if isinstance(data, dict) else {}

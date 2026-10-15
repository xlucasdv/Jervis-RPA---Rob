"""Interface web da equipe: revisão dos relatórios mensais.

Quem entra: contas Microsoft 365 da organização (Entra ID) cadastradas no Jervis com um perfil:
- leitura: vê os relatórios e abre os arquivos;
- revisor: também aprova e rejeita;
- admin: também gera de novo e desfaz revisões.

Proteções: só aceita conexões das redes configuradas (rede interna/VPN), sempre por HTTPS (server.py); sessão em
cookie assinado (Secure, HttpOnly, SameSite); toda ação exige o token da sessão (contra requisições forjadas por
outros sites); o perfil é relido do banco a cada requisição (acesso suspenso vale na hora); arquivos só da pasta
de saída e de uma lista fixa; cada ação fica na trilha de auditoria com o nome da pessoa e o IP.
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, abort, g, jsonify, redirect, request, send_file, session

from jervis import db, scheduling
from jervis.audit import AuditLog
from jervis.db import repository
from jervis.errors import JervisError
from jervis.security import redact
from jervis.web.auth import AuthError, EntraAuth
from jervis.web.jobs import Job, Jobs

log = logging.getLogger(__name__)

CLIENT_SECRET = "web:client_secret"
SESSION_SECRET = "web:session_key"
ROLE_LEVEL = {"leitura": 1, "revisor": 2, "admin": 3}
# Arquivos que a interface entrega (nada fora desta lista, nem fora da pasta de saída)
FILES = {
    "relatorio_executivo.pdf": ("Relatório executivo", "Visão para a diretoria", True),
    "relatorio_mensal.pdf": ("Relatório mensal", "Relatório detalhado do mês", True),
    "relatorio_mensal.xlsx": ("Planilha", "Registros do mês, para filtrar", False),
    "resumo.md": ("Resumo", "Texto de apoio para a equipe", False),
}
_STATUS_IN_HEAD = re.compile(r'"status":\s*"(\w+)"')
_COUNTS_IN_HEAD = re.compile(r'"counts":\s*(\{[^{}]*\})')

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://login.microsoftonline.com")


def session_key(store) -> str:
    """Chave que assina os cookies de sessão: criada na primeira vez e guardada no cofre."""
    key = store.get_secret(SESSION_SECRET)
    if not key:
        key = secrets.token_urlsafe(48)
        store.set_secret(SESSION_SECRET, key)
    return key


def create_app(config, store, auth: EntraAuth | None = None, connect: Callable[[], Any] | None = None,
               jobs: Jobs | None = None, run_customer: Callable | None = None) -> Flask:
    web = config.web
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.update(
        SECRET_KEY=session_key(store), SESSION_COOKIE_NAME="jervis_session", SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=web.session_hours), MAX_CONTENT_LENGTH=64 * 1024,
    )
    networks = [ipaddress.ip_network(n, strict=False) for n in web.allowed_networks]
    output_dir = Path(config.settings.output_dir).resolve()
    auth = auth or EntraAuth(web.tenant_id, web.client_id, lambda: store.get_secret(CLIENT_SECRET), web.redirect_uri)
    connect = connect or (lambda: db.connect(config.database, store))
    trail = AuditLog(config.settings.audit_file, config.environment)

    @contextlib.contextmanager
    def database():
        conn = connect()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def audit(event: str, **details) -> None:
        user = g.get("user")
        by = {"usuario": user.email if user else "anônimo", "maquina": socket.gethostname(), "acesso": "web",
              "ip": request.remote_addr or "?"}
        try:
            trail.record(event, by=by, **details)
        except OSError as exc:  # a ação já foi feita; registra no log da aplicação
            log.error("Auditoria não registrada (%s): %s", event, exc)

    # --- geração em segundo plano ---------------------------------------------------------

    def regenerate(job: Job) -> tuple[str, int | None, str]:
        from jervis.api import closing, collect

        if run_customer is None:
            from jervis.api.run import run_customer as runner
        else:
            runner = run_customer
        period = collect.month(job.competencia)
        with database() as conn:
            customer = repository.find_customer(conn, str(job.customer_id))
            outcome = closing.run_customers(config, store, conn, [customer], period, runner, origin="web",
                                            user=job.requested_by, emit=lambda line: log.info("%s", line))[0]
        try:
            trail.record("relatorio_cliente", by={"usuario": job.requested_by, "maquina": socket.gethostname(),
                                                  "acesso": "web"},
                         cliente=customer.name, competencia=job.competencia, resultado=outcome.resultado,
                         revisao=outcome.report_id, execucao=str(outcome.run_dir) if outcome.run_dir else None)
        except OSError as exc:
            log.error("Auditoria não registrada (relatorio_cliente): %s", exc)
        return outcome.resultado, outcome.report_id, outcome.detalhe

    jobs = jobs or Jobs(regenerate)

    # --- proteções em toda requisição ------------------------------------------------------

    @app.before_request
    def guard():
        try:
            address = ipaddress.ip_address((request.remote_addr or "").split("%")[0])
        except ValueError:
            abort(403)
        if not any(address in net for net in networks):
            log.warning("Acesso recusado de %s (fora das redes permitidas)", address)
            abort(403)
        g.user = None
        if request.path.startswith("/static/"):
            return None
        user_id = session.get("user_id")
        if user_id:
            with database() as conn:
                user = repository.get_web_user(conn, user_id)
            if user and user.active and user.email == session.get("email"):
                g.user = user
            else:
                session.clear()
        if request.method not in ("GET", "HEAD"):
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf") or ""
            if not g.user or not hmac.compare_digest(token, session.get("csrf", "")):
                abort(403)

    @app.after_request
    def headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if request.path.startswith(("/api/", "/files/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    def require(role: str):
        def decorator(view):
            @wraps(view)
            def wrapper(*args, **kwargs):
                if not g.user:
                    return jsonify(erro="Sessão expirada. Entre de novo."), 401
                if ROLE_LEVEL.get(g.user.role, 0) < ROLE_LEVEL[role]:
                    return jsonify(erro=f"Seu perfil ({g.user.role}) não permite essa ação."), 403
                return view(*args, **kwargs)
            return wrapper
        return decorator

    @app.errorhandler(JervisError)
    def jervis_error(exc):
        return jsonify(erro=redact(str(exc))), 400

    @app.errorhandler(403)
    def forbidden(exc):
        if request.path.startswith("/api/"):
            return jsonify(erro="Acesso negado."), 403
        return _page("Acesso negado", "Este endereço não está liberado para você."), 403

    # --- login ------------------------------------------------------------------------------

    @app.get("/login")
    def login():
        missing = web.missing()
        if missing:
            return _page("Interface não configurada",
                         f"Falta preencher na seção web da configuração: {', '.join(missing)}. Veja 'jervis web check'."), 503
        try:
            flow = auth.begin()
        except AuthError as exc:
            return _page("Login indisponível", str(exc)), 503
        session.clear()
        session["flow"] = flow
        return redirect(flow["auth_uri"])

    @app.get("/auth/callback")
    def callback():
        flow = session.pop("flow", None)
        if not flow:
            return redirect("/login")
        try:
            identity = auth.finish(flow, request.args.to_dict())
        except AuthError as exc:
            return _page("Não foi possível entrar", str(exc), retry=True), 401
        with database() as conn:
            user = repository.find_web_user(conn, identity.email)
            if not user or not user.active:
                log.warning("Login recusado: %s sem acesso liberado", identity.email)
                return _page("Acesso ainda não liberado",
                             f"A conta {identity.email} entrou na Microsoft, mas não tem acesso ao Jervis. "
                             f"Peça a um administrador: jervis web users add {identity.email} --role revisor"), 403
            if user.entra_oid and identity.oid and user.entra_oid != identity.oid:
                log.warning("Login recusado: %s com ID de conta diferente do primeiro login", identity.email)
                return _page("Acesso negado", "Essa conta não é a mesma que recebeu o acesso. Fale com um administrador."), 403
            repository.record_web_login(conn, user.id, identity.oid, identity.name)
        session.clear()
        session.permanent = True
        session.update(user_id=user.id, email=user.email, csrf=secrets.token_urlsafe(32))
        g.user = user
        audit("web_login", nome=identity.name)
        return redirect("/")

    @app.post("/logout")
    def logout():
        audit("web_logout")
        session.clear()
        return redirect("/saiu")

    @app.get("/saiu")
    def logged_out():
        return _page("Você saiu do Jervis", "Para entrar de novo, use o botão abaixo.", retry=True)

    # --- página -------------------------------------------------------------------------

    @app.get("/")
    def index():
        if not g.user:
            return redirect("/login")
        return app.send_static_file("index.html")

    # --- API ------------------------------------------------------------------------------

    @app.get("/api/me")
    @require("leitura")
    def me():
        u = g.user
        return jsonify(email=u.email, nome=u.name or u.email, perfil=u.role, csrf=session["csrf"])

    @app.get("/api/overview")
    @require("leitura")
    def overview():
        with database() as conn:
            months = repository.list_competencias(conn)
        now = datetime.now()
        closes = [s for s in config.schedules.values() if s.enabled and s.task == "relatorios_clientes"]
        upcoming = min((scheduling.next_run(s, now) for s in closes), default=None)
        return jsonify(competencias=months, proximo_fechamento=upcoming.strftime("%d/%m %H:%M") if upcoming else None)

    @app.get("/api/reviews")
    @require("leitura")
    def reviews():
        month = request.args.get("month") or None
        if month and not re.fullmatch(r"\d{4}-\d{2}", month):
            return jsonify(erro="Competência inválida (use AAAA-MM)."), 400
        with database() as conn:
            reports = [r for r in repository.list_reports(conn, None, month) if r.status != "substituido"]
            names = {u.email: u.name for u in repository.list_web_users(conn)}
        return jsonify(relatorios=[_summary(r, names) for r in reports], jobs=jobs.list())

    @app.get("/api/reviews/<int:report_id>")
    @require("leitura")
    def review_detail(report_id: int):
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            names = {u.email: u.name for u in repository.list_web_users(conn)}
        data = _summary(report, names)
        data["plataformas"] = _platforms(report, full=True)
        data["arquivos"] = [{"nome": name, "titulo": t, "descricao": d, "vai_ao_cliente": send}
                            for name, (t, d, send) in FILES.items() if _file(report, name)]
        return jsonify(data)

    @app.post("/api/reviews/<int:report_id>/approve")
    @require("revisor")
    def approve(report_id: int):
        note = _text("nota", 1024)
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            repository.review_report(conn, report.id, "aprovado", g.user.email, note)
        audit("relatorio_aprovado", revisao=report.id, cliente=report.customer, competencia=report.competencia,
              pasta=report.run_dir, observacao=note)
        return jsonify(ok=True, mensagem=f"{report.customer}: aprovado.")

    @app.post("/api/reviews/approve")
    @require("revisor")
    def approve_many():
        body = request.get_json(silent=True) or {}
        ids = body.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids) or len(ids) > 500:
            return jsonify(erro="Selecione os relatórios a aprovar."), 400
        approved, skipped = [], []
        with database() as conn:
            for report_id in ids:
                report = repository.find_report(conn, f"#{report_id}")
                if report.status != "pendente":
                    skipped.append(report.customer)
                    continue
                repository.review_report(conn, report.id, "aprovado", g.user.email, None)
                approved.append(report)
        for report in approved:
            audit("relatorio_aprovado", revisao=report.id, cliente=report.customer, competencia=report.competencia,
                  pasta=report.run_dir, em_lote=True)
        message = f"{len(approved)} relatório(s) aprovado(s)."
        if skipped:
            message += f" {len(skipped)} já não estavam pendentes: {', '.join(skipped)}."
        return jsonify(ok=True, mensagem=message, aprovados=[r.id for r in approved])

    @app.post("/api/reviews/<int:report_id>/reject")
    @require("revisor")
    def reject(report_id: int):
        reason = _text("motivo", 1024)
        if not reason:
            return jsonify(erro="Escreva o motivo da rejeição."), 400
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            repository.review_report(conn, report.id, "rejeitado", g.user.email, reason)
        audit("relatorio_rejeitado", revisao=report.id, cliente=report.customer, competencia=report.competencia,
              pasta=report.run_dir, observacao=reason)
        return jsonify(ok=True, mensagem=f"{report.customer}: rejeitado.")

    @app.post("/api/reviews/<int:report_id>/reopen")
    @require("admin")
    def reopen(report_id: int):
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            repository.reopen_report(conn, report.id)
        audit("relatorio_reaberto", revisao=report.id, cliente=report.customer, competencia=report.competencia,
              situacao_anterior=report.status)
        return jsonify(ok=True, mensagem=f"{report.customer} voltou para pendente.")

    @app.post("/api/reviews/<int:report_id>/regenerate")
    @require("admin")
    def regenerate_report(report_id: int):
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
        if not report.competencia:
            return jsonify(erro="Só relatórios mensais podem ser gerados de novo pela interface."), 400
        job = jobs.submit(report.customer_id, report.customer, report.competencia, g.user.email)
        audit("relatorio_pedido", revisao=report.id, cliente=report.customer, competencia=report.competencia, fila=job.id)
        return jsonify(ok=True, mensagem=f"{report.customer}: geração na fila. Leva cerca de um minuto.", job=job.id)

    @app.get("/api/jobs")
    @require("leitura")
    def job_list():
        return jsonify(jobs=jobs.list())

    @app.get("/files/<int:report_id>/<name>")
    @require("leitura")
    def file(report_id: int, name: str):
        if name not in FILES:
            abort(404)
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
        path = _file(report, name)
        if not path:
            abort(404)
        audit("relatorio_aberto", revisao=report.id, cliente=report.customer, arquivo=name)
        pdf = name.endswith(".pdf")
        download = f"{_slug(report.customer)}_{report.competencia or 'periodo'}_{name}"
        return send_file(path, as_attachment=not pdf, download_name=download,
                         mimetype="text/markdown; charset=utf-8" if name.endswith(".md") else None)

    # --- auxiliares ---------------------------------------------------------------------

    def _file(report, name: str) -> Path | None:
        if not report.run_dir:
            return None
        folder = Path(report.run_dir).resolve()
        if not folder.is_relative_to(output_dir):  # pasta registrada fora da saída: nunca entrega
            log.warning("Pasta fora da saída recusada: %s", folder)
            return None
        path = folder / name
        return path if path.is_file() else None

    def _summary(report, names: dict[str, str | None]) -> dict[str, Any]:
        return {
            "id": report.id, "cliente": report.customer, "cliente_id": report.customer_id,
            "competencia": report.competencia, "periodo": report.periodo, "resultado": report.resultado,
            "situacao": report.status, "origem": report.origem, "gerado_por": report.gerado_por,
            "gerado_em": _local(report.gerado_em), "revisado_por": names.get(report.revisado_por) or report.revisado_por,
            "revisado_em": _local(report.revisado_em), "observacao": report.observacao,
            "plataformas": _platforms(report),
        }

    return app


def _text(field: str, limit: int) -> str | None:
    value = (request.get_json(silent=True) or {}).get(field) or ""
    return (value.strip()[:limit] or None) if isinstance(value, str) else None


def _local(moment) -> str | None:
    """Datas do banco ficam em UTC sem fuso: mostra no horário desta máquina."""
    if not moment:
        return None
    return moment.replace(tzinfo=timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "cliente"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _platforms(report, full: bool = False) -> list[dict[str, Any]]:
    """Situação de cada plataforma na geração. Na lista, lê só o começo de cada arquivo (alguns têm milhares de
    registros); no detalhe, o arquivo inteiro, para mostrar erros e avisos."""
    if not report.run_dir:
        return []
    folder = Path(report.run_dir)
    services = _read_json(folder / "cliente.json").get("servicos") or {}
    platforms = []
    for slug, external in services.items():
        path = folder / f"{slug}.json"
        item: dict[str, Any] = {"plataforma": slug, "nome_na_plataforma": external, "status": "falha", "contagens": {}}
        if full:
            data = _read_json(path)
            issues = data.get("issues") or []
            item.update(status=data.get("status", "falha"), contagens=data.get("counts") or {},
                        erros=[i.get("message") for i in issues if i.get("severity") == "erro"][:5],
                        avisos=[i.get("message") for i in issues if i.get("severity") == "aviso"][:8])
        else:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(4096)
            except OSError:
                head = ""
            status, counts = _STATUS_IN_HEAD.search(head), _COUNTS_IN_HEAD.search(head)
            item["status"] = status.group(1) if status else "falha"
            if counts:
                with contextlib.suppress(ValueError):
                    item["contagens"] = json.loads(counts.group(1))
        platforms.append(item)
    return platforms


def _page(title: str, message: str, retry: bool = False) -> str:
    """Páginas simples (fora da aplicação): login recusado, acesso negado, saída."""
    from html import escape

    button = '<a class="btn" href="/login">Entrar com a conta Microsoft</a>' if retry else ""
    return (f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width, initial-scale=1"><title>{escape(title)} · Jervis3000</title>'
            f'<link rel="stylesheet" href="/static/app.css"></head><body class="plain"><main class="plain-box">'
            f'<b class="brand">Jervis3000</b><h1>{escape(title)}</h1><p>{escape(message)}</p>{button}</main></body></html>')

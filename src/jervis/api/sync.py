"""Clientes que existem numa plataforma (Acronis: locatários do tipo cliente; Zabbix: grupos de hosts) comparados
com o cadastro do Jervis, e a importação dos que faltam (cadastra o cliente e cria o vínculo)."""

from __future__ import annotations

from dataclasses import dataclass

from jervis.db import repository

LINKED, UNLINKED, NEW, AMBIGUOUS = "vinculado", "cadastrado, sem vínculo", "não cadastrado", "nome repetido no cadastro"


@dataclass
class PlatformCustomer:
    name: str  # como aparece na plataforma
    status: str
    customer: repository.Customer | None = None


def _key(text: str) -> str:
    return (text or "").strip().lower()


def _linked_name(customer: repository.Customer, slug: str, aliases: dict[str, str]) -> str:
    """Nome na plataforma do vínculo; se o vínculo usa um apelido (ex.: id do tenant), o nome correspondente."""
    name = customer.name_on(slug)
    return {_key(k): v for k, v in aliases.items()}.get(_key(name), name)


def compare(names: list[str], customers: list[repository.Customer], slug: str,
            aliases: dict[str, str] | None = None) -> list[PlatformCustomer]:
    """Situação de cada cliente da plataforma no cadastro: vinculado (pelo nome na plataforma do vínculo),
    cadastrado com o mesmo nome mas sem vínculo, ou não cadastrado. ``aliases``: outras formas de apontar um
    cliente na plataforma (ex.: id do tenant no Sophos) → nome."""
    aliases = aliases or {}
    linked = {_key(_linked_name(c, slug, aliases)): c for c in customers if slug in c.services}
    by_name: dict[str, list[repository.Customer]] = {}
    for c in customers:
        by_name.setdefault(_key(c.name), []).append(c)
    rows = []
    for name in names:
        if _key(name) in linked:
            rows.append(PlatformCustomer(name, LINKED, linked[_key(name)]))
            continue
        same = [c for c in by_name.get(_key(name), []) if slug not in c.services]
        if len(same) == 1:
            rows.append(PlatformCustomer(name, UNLINKED, same[0]))
        elif same:
            rows.append(PlatformCustomer(name, AMBIGUOUS))
        else:
            rows.append(PlatformCustomer(name, NEW))
    return rows


def orphans(names: list[str], customers: list[repository.Customer], slug: str,
            aliases: dict[str, str] | None = None) -> list[repository.Customer]:
    """Clientes vinculados ao serviço cujo nome na plataforma não existe mais nela (renomeado ou removido)."""
    found = {_key(n) for n in names}
    return [c for c in customers if slug in c.services and _key(_linked_name(c, slug, aliases or {})) not in found]


def import_missing(conn, rows: list[PlatformCustomer], slug: str) -> list[tuple[str, bool]]:
    """Cadastra os não cadastrados e vincula ao serviço (o nome na plataforma é o próprio nome do cadastro).
    Devolve (nome, cliente_criado) de cada vínculo criado. Não faz commit."""
    done = []
    for row in rows:
        if row.status == NEW:
            customer_id = repository.add_customer(conn, row.name, None)
            repository.link(conn, str(customer_id), slug)
            done.append((row.name, True))
        elif row.status == UNLINKED:
            repository.link(conn, str(row.customer.id), slug)
            done.append((row.name, False))
    return done

"""Banco de dados (MySQL): conexão e criação das tabelas.

Endereço, porta e nome do banco vêm da seção ``database`` do arquivo de configuração; usuário e senha, do
cofre do sistema (``jervis db set-credentials``) ou de JERVIS_DATABASE_USERNAME / JERVIS_DATABASE_PASSWORD.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

import pymysql

from jervis.config import DatabaseConfig
from jervis.credentials import CredentialStore
from jervis.db.schema import ADDED_COLUMNS, TABLE_NAMES, TABLES
from jervis.errors import CredentialsNotFoundError, JervisError

log = logging.getLogger(__name__)

# Nome das credenciais do banco no cofre e nas variáveis de ambiente (JERVIS_DATABASE_*).
CREDENTIALS_NAME = "database"

# Erros do MySQL com mensagem própria para o operador.
_ACCESS_DENIED, _UNKNOWN_DATABASE, _CANT_CONNECT, _UNKNOWN_HOST = 1045, 1049, 2003, 2005


class DatabaseError(JervisError):
    """Não foi possível acessar ou preparar o banco de dados."""


def connect(db: DatabaseConfig, store: CredentialStore, database: bool = True,
            connector: Callable[..., Any] = pymysql.connect):
    """Abre uma conexão. ``database=False`` conecta ao servidor sem escolher o banco (para criá-lo)."""
    try:
        creds = store.get(CREDENTIALS_NAME)
    except CredentialsNotFoundError as exc:
        raise DatabaseError(
            "Credenciais do banco não cadastradas. Use 'jervis db set-credentials' "
            "ou defina JERVIS_DATABASE_USERNAME e JERVIS_DATABASE_PASSWORD."
        ) from exc
    try:
        return connector(
            host=db.host, port=db.port, user=creds.username, password=creds.password.reveal(),
            database=db.name if database else None, charset="utf8mb4", connect_timeout=db.connect_timeout,
            autocommit=False, init_command="SET time_zone = '+00:00'",  # datas do banco sempre em UTC
        )
    except pymysql.err.OperationalError as exc:
        raise DatabaseError(_friendly(exc, db)) from exc


def _friendly(exc: pymysql.err.OperationalError, db: DatabaseConfig) -> str:
    code = exc.args[0] if exc.args else None
    where = f"{db.host}:{db.port}"
    if code == _ACCESS_DENIED:
        return f"O MySQL em {where} recusou o usuário ou a senha. Atualize com 'jervis db set-credentials'."
    if code == _UNKNOWN_DATABASE:
        return f"O banco '{db.name}' não existe em {where} e o usuário não tem permissão para criá-lo."
    if code in (_CANT_CONNECT, _UNKNOWN_HOST):
        return (f"Não foi possível conectar ao MySQL em {where}. Verifique se o servidor está no ar "
                "(ex.: 'docker compose up -d mysql') e a seção 'database' da configuração.")
    return f"Erro do MySQL em {where}: {exc.args[-1] if exc.args else exc}"


def ensure_schema(db: DatabaseConfig, store: CredentialStore, connector: Callable[..., Any] = pymysql.connect) -> list[str]:
    """Cria o banco (se o usuário puder), as tabelas que ainda não existem e as colunas novas que faltam
    em tabelas antigas. Devolve o que foi criado ("tabela" ou "tabela.coluna")."""
    server = connect(db, store, database=False, connector=connector)
    try:
        with server.cursor() as cur:
            try:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db.name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci")
            except pymysql.err.MySQLError as exc:  # sem permissão: o banco precisa já existir
                log.info("Banco %s não criado (%s); usando o existente", db.name, exc)
    finally:
        server.close()

    conn = connect(db, store, connector=connector)
    try:
        with conn.cursor() as cur:
            existing = _existing_tables(cur)
            created = []
            for name, ddl in TABLES:
                if name not in existing:
                    cur.execute(ddl)
                    created.append(name)
            columns = _existing_columns(cur)
            for table, column, definition in ADDED_COLUMNS:
                if table in existing and (table, column) not in columns:
                    cur.execute(f"ALTER TABLE `{table}` ADD COLUMN {definition}")
                    created.append(f"{table}.{column}")
        conn.commit()
    except pymysql.err.MySQLError as exc:
        raise DatabaseError(f"Não foi possível criar as tabelas em '{db.name}': {exc.args[-1] if exc.args else exc}") from exc
    finally:
        conn.close()
    if created:
        log.info("Tabelas criadas em %s: %s", db.name, ", ".join(created))
    return created


def table_status(db: DatabaseConfig, store: CredentialStore, connector: Callable[..., Any] = pymysql.connect) -> dict[str, int | None]:
    """Quantidade de linhas de cada tabela do projeto (None = tabela ainda não existe)."""
    conn = connect(db, store, connector=connector)
    try:
        with conn.cursor() as cur:
            existing = _existing_tables(cur)
            status: dict[str, int | None] = {}
            for name in TABLE_NAMES:
                if name in existing:
                    cur.execute(f"SELECT COUNT(*) FROM `{name}`")
                    status[name] = cur.fetchone()[0]
                else:
                    status[name] = None
            return status
    finally:
        conn.close()


def _existing_columns(cur) -> set[tuple[str, str]]:
    cur.execute("SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE()")
    return {(row[0], row[1]) for row in cur.fetchall()}


def _existing_tables(cur) -> set[str]:
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
    return {row[0] for row in cur.fetchall()}

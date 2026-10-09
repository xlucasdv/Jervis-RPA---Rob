"""Banco de dados: configuração, criação das tabelas, criptografia da chave MFA e comandos."""

import os

import pymysql
import pytest
import yaml

from jervis import cli, db
from jervis.config import DatabaseConfig, parse_config
from jervis.credentials import CredentialStore
from jervis.db import crypto
from jervis.db.schema import ADDED_COLUMNS, TABLE_NAMES, TABLES
from jervis.errors import ConfigError

DB = DatabaseConfig(host="127.0.0.1", port=3306, name="jervis_teste")


# --- configuração --------------------------------------------------------------------


def test_database_section_is_optional_and_parsed():
    assert parse_config({}).database is None
    config = parse_config({"database": {"host": "db.local", "port": 3307, "name": "jervis"}})
    assert config.database == DatabaseConfig(host="db.local", port=3307, name="jervis")


@pytest.mark.parametrize("section, message", [
    ({"port": 0}, "porta"),
    ({"name": "jervis; drop"}, "letras, números"),
    ({"user": "root"}, "Credenciais não podem"),
    ({"password": "x"}, "Credenciais não podem"),
    ({"hostname": "x"}, "desconhecid|não reconhecid|inválid"),
])
def test_invalid_database_section(section, message):
    with pytest.raises(ConfigError, match=message):
        parse_config({"database": section})


# --- esquema ------------------------------------------------------------------------


def test_tables_and_creation_order():
    assert TABLE_NAMES == ["customers", "service", "customer_services"]  # referenciadas antes
    ddl = dict(TABLES)
    assert all(sql.lstrip().startswith(f"CREATE TABLE IF NOT EXISTS {name} (") for name, sql in TABLES)
    assert "desk_manager_id" in ddl["customers"] and "name VARCHAR(255) NOT NULL" in ddl["customers"]
    for column in ("url", "slug", "class_identifier", "settings JSON"):
        assert column in ddl["service"]
    assert "REFERENCES customers (id)" in ddl["customer_services"]
    assert "REFERENCES service (id)" in ddl["customer_services"]
    assert "mfa_secret_encrypted" in ddl["customer_services"]


class FakeCursor:
    def __init__(self, server):
        self.server = server

    def execute(self, sql, params=None):
        self.server.executed.append(" ".join(sql.split()))
        self.last = sql

    def fetchall(self):
        if "information_schema.columns" in self.last:
            return sorted(self.server.columns)
        return [(name,) for name in self.server.existing]

    def fetchone(self):
        return (0,)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeServer:
    """Imita o pymysql.connect: registra os comandos e as conexões abertas."""

    def __init__(self, existing=(), columns=None):
        self.existing = set(existing)
        # colunas já existentes; por padrão, as acrescentadas depois da 1ª versão já estão lá
        self.columns = set(columns) if columns is not None else {(t, c) for t, c, _ in ADDED_COLUMNS}
        self.executed, self.connections = [], []

    def __call__(self, **kwargs):
        self.connections.append(kwargs)
        server = self

        class Conn:
            def cursor(self):
                return FakeCursor(server)

            def commit(self):
                pass

            def close(self):
                pass

        return Conn()


@pytest.fixture
def store(memory_keyring):
    s = CredentialStore("jervis3000-teste")
    s.set(db.CREDENTIALS_NAME, "jervis", "S3nh@-do-banco")
    return s


def test_ensure_schema_creates_only_missing_tables(store):
    server = FakeServer(existing={"customers"})
    created = db.ensure_schema(DB, store, connector=server)
    assert created == ["service", "customer_services"]
    assert server.executed[0].startswith("CREATE DATABASE IF NOT EXISTS `jervis_teste`")
    assert not any("CREATE TABLE IF NOT EXISTS customers" in sql for sql in server.executed)
    assert server.connections[0]["database"] is None and server.connections[1]["database"] == "jervis_teste"
    assert server.connections[1]["user"] == "jervis" and server.connections[1]["password"] == "S3nh@-do-banco"


def test_ensure_schema_when_everything_exists(store):
    assert db.ensure_schema(DB, store, connector=FakeServer(existing=TABLE_NAMES)) == []


def test_ensure_schema_adds_new_columns_to_old_tables(store):
    server = FakeServer(existing=TABLE_NAMES, columns=set())  # banco criado na 1ª versão
    created = db.ensure_schema(DB, store, connector=server)
    assert created == ["service.mfa_secret_encrypted", "customer_services.external_name", "customer_services.products",
                       "customer_services.contracted_devices"]
    alters = [sql for sql in server.executed if sql.startswith("ALTER TABLE")]
    assert alters[0].startswith("ALTER TABLE `service` ADD COLUMN mfa_secret_encrypted") and alters[0].endswith("AFTER settings")
    assert "DROP" not in " ".join(server.executed)


def test_missing_credentials(memory_keyring):
    with pytest.raises(db.DatabaseError, match="jervis db set-credentials"):
        db.ensure_schema(DB, CredentialStore("vazio"), connector=FakeServer())


@pytest.mark.parametrize("code, message", [
    (1045, "recusou o usuário ou a senha"),
    (2003, "Não foi possível conectar ao MySQL em 127.0.0.1:3306"),
    (1049, "não existe"),
])
def test_friendly_connection_errors(store, code, message):
    def refuse(**kwargs):
        raise pymysql.err.OperationalError(code, "detalhe do servidor")

    with pytest.raises(db.DatabaseError, match=message) as info:
        db.ensure_schema(DB, store, connector=refuse)
    assert "S3nh@-do-banco" not in str(info.value)


# --- criptografia da chave MFA --------------------------------------------------------


def test_mfa_secret_roundtrip_and_wrong_key():
    key = crypto.new_key()
    token = crypto.encrypt_secret("JBSWY3DPEHPK3PXP", key)
    assert "JBSWY3DPEHPK3PXP" not in token and token.isascii()
    assert crypto.decrypt_secret(token, key).reveal() == "JBSWY3DPEHPK3PXP"
    with pytest.raises(crypto.EncryptionKeyError, match="diferente da usada"):
        crypto.decrypt_secret(token, crypto.new_key())
    with pytest.raises(crypto.EncryptionKeyError, match="inválida"):
        crypto.encrypt_secret("x", "não é uma chave")


def test_key_from_env_or_vault(memory_keyring):
    store = CredentialStore("jervis3000-teste")
    with pytest.raises(crypto.EncryptionKeyError, match="jervis db generate-key"):
        crypto.load_key(store, environ={})
    store.set_secret(crypto.VAULT_KEY, "do-cofre")
    assert crypto.load_key(store, environ={}) == "do-cofre"
    assert crypto.load_key(store, environ={crypto.ENV_KEY: "da-variavel"}) == "da-variavel"


# --- comandos e ponto de entrada -------------------------------------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    return tmp_path


def run(*args):
    return cli.main(["-c", "platforms.yaml", *args])


def with_database(project):
    path = project / "platforms.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["database"] = {"host": "127.0.0.1", "port": 3306, "name": "jervis_teste"}
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")


def test_entry_point_creates_tables_when_database_is_configured(project, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(db, "ensure_schema", lambda database, store: calls.append(database.name) or ["customers"])
    assert run("platforms", "list") == 0
    assert calls == []  # sem seção database, nada é feito
    with_database(project)
    assert run("platforms", "list") == 0
    assert calls == ["jervis_teste"]
    assert "Estrutura do banco 'jervis_teste' atualizada: customers" in capsys.readouterr().out


def test_entry_point_continues_when_database_is_down(project, monkeypatch, capsys):
    with_database(project)

    def down(database, store):
        raise db.DatabaseError("Não foi possível conectar ao MySQL em 127.0.0.1:3306.")

    monkeypatch.setattr(db, "ensure_schema", down)
    assert run("platforms", "list") == 0
    assert "tabelas do banco não verificadas" in capsys.readouterr().err


def test_db_setup_commands_do_not_trigger_creation(project, monkeypatch):
    with_database(project)
    monkeypatch.setattr(db, "ensure_schema", lambda *a, **k: pytest.fail("não deveria criar tabelas aqui"))
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "S3nh@-do-banco")
    assert run("db", "set-credentials", "--username", "jervis") == 0
    assert CredentialStore().get(db.CREDENTIALS_NAME).username == "jervis"
    assert run("db", "generate-key") == 0
    assert run("db", "generate-key") == 1  # não substitui sem --force
    assert run("db", "generate-key", "--force") == 0


def test_db_commands_require_database_section(project, capsys):
    assert run("db", "init") == 1
    assert "seção 'database'" in capsys.readouterr().err


# --- integração com um MySQL de verdade (opcional) --------------------------------------
# Ex.: $env:JERVIS_TEST_MYSQL = "127.0.0.1:3307:root:senha"  (banco descartável: o teste cria jervis_teste_integracao)

# lido na importação: a fixture memory_keyring remove as variáveis JERVIS_* antes de cada teste
MYSQL = os.environ.get("JERVIS_TEST_MYSQL", "")


@pytest.mark.skipif(not MYSQL, reason="defina JERVIS_TEST_MYSQL para testar com um MySQL real")
def test_real_mysql_schema_constraints_and_encrypted_mfa(memory_keyring):
    host, port, user, password = MYSQL.split(":", 3)
    config = DatabaseConfig(host=host, port=int(port), name="jervis_teste_integracao")
    store = CredentialStore("jervis3000-teste")
    store.set(db.CREDENTIALS_NAME, user, password)

    assert set(db.ensure_schema(config, store)) <= set(TABLE_NAMES)
    assert db.ensure_schema(config, store) == []  # idempotente
    key = crypto.new_key()
    conn = db.connect(config, store)
    try:
        with conn.cursor() as cur:
            for table in ("customer_services", "customers", "service"):
                cur.execute(f"DELETE FROM {table}")
            cur.execute("INSERT INTO customers (name, desk_manager_id) VALUES (%s, %s)", ("MERCOS", "DM-123"))
            customer_id = cur.lastrowid
            cur.execute("INSERT INTO service (slug, url, class_identifier, settings) VALUES (%s, %s, %s, %s)",
                        ("acronis", "https://br02-cloud.acronis.com", "acronis", '{"mfa": "totp"}'))
            service_id = cur.lastrowid
            cur.execute("INSERT INTO customer_services (customer_id, service_id, mfa_secret_encrypted) VALUES (%s, %s, %s)",
                        (customer_id, service_id, crypto.encrypt_secret("JBSWY3DPEHPK3PXP", key)))
            with pytest.raises(pymysql.err.IntegrityError):  # mesmo cliente + serviço duas vezes
                cur.execute("INSERT INTO customer_services (customer_id, service_id) VALUES (%s, %s)", (customer_id, service_id))
            with pytest.raises(pymysql.err.IntegrityError):  # serviço inexistente
                cur.execute("INSERT INTO customer_services (customer_id, service_id) VALUES (%s, %s)", (customer_id, 999999))
            cur.execute("SELECT mfa_secret_encrypted FROM customer_services WHERE customer_id = %s", (customer_id,))
            token = cur.fetchone()[0]
            assert crypto.decrypt_secret(token, key).reveal() == "JBSWY3DPEHPK3PXP"
            with pytest.raises(pymysql.err.IntegrityError):  # serviço em uso não pode ser apagado
                cur.execute("DELETE FROM service WHERE id = %s", (service_id,))
            cur.execute("DELETE FROM customers WHERE id = %s", (customer_id,))  # apaga os vínculos junto
            cur.execute("SELECT COUNT(*) FROM customer_services")
            assert cur.fetchone()[0] == 0
        conn.commit()
    finally:
        conn.close()
    assert db.table_status(config, store) == {"customers": 0, "service": 1, "customer_services": 0}

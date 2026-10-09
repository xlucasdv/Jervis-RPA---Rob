"""Cadastro de clientes, serviços e vínculos (jervis customers / jervis services)."""

import os
import uuid

import pymysql
import pytest
import yaml

from jervis import cli, db
from jervis.config import DatabaseConfig
from jervis.credentials import CredentialStore
from jervis.db import crypto, repository
from jervis.errors import ConfigError

# lido na importação: a fixture memory_keyring remove as variáveis JERVIS_* antes de cada teste
MYSQL = os.environ.get("JERVIS_TEST_MYSQL", "")
TOTP = "JBSWY3DPEHPK3PXP"


# --- regras sem banco ------------------------------------------------------------------


def test_settings_from_pairs():
    assert cli._settings_from(["mfa=totp", "login_timeout=45", "ativo=true", 'pages={"a": "/x"}']) == {
        "mfa": "totp", "login_timeout": 45, "ativo": True, "pages": {"a": "/x"}}
    with pytest.raises(ConfigError, match="CHAVE=VALOR"):
        cli._settings_from(["sem-igual"])
    with pytest.raises(ConfigError, match="credencial"):
        cli._settings_from(["password=123"])


def test_class_identifier_must_be_a_collector_or_python_path():
    assert cli._checked_class("acronis") == "acronis"
    assert cli._checked_class("pacote.modulo.Classe") == "pacote.modulo.Classe"
    with pytest.raises(ConfigError, match="desconhecida"):
        cli._checked_class("acronys")


# --- fluxo completo com MySQL de verdade -----------------------------------------------

pytestmark_mysql = pytest.mark.skipif(not MYSQL, reason="defina JERVIS_TEST_MYSQL para testar com um MySQL real")


@pytest.fixture
def project(tmp_path, monkeypatch, memory_keyring):
    """Projeto com banco descartável (um por teste) e chave de criptografia no cofre em memória."""
    host, port, user, password = MYSQL.split(":", 3)
    name = f"jervis_teste_{uuid.uuid4().hex[:8]}"
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    path = tmp_path / "platforms.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["database"] = {"host": host, "port": int(port), "name": name}
    data["settings"]["audit_file"] = str(tmp_path / "auditoria.jsonl")
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    store = CredentialStore()
    store.set(db.CREDENTIALS_NAME, user, password)
    store.set_secret(crypto.VAULT_KEY, crypto.new_key())
    yield tmp_path, DatabaseConfig(host=host, port=int(port), name=name), store
    conn = pymysql.connect(host=host, port=int(port), user=user, password=password)
    with conn.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
    conn.close()


def run(*args):
    return cli.main(["-c", "platforms.yaml", *args])


@pytestmark_mysql
def test_services_lifecycle(project, capsys):
    assert run("services", "add", "acronis", "--url", "https://br02-cloud.acronis.com", "--class", "acronis",
               "--set", "mfa=totp", "--set", "login_timeout=45") == 0
    assert "Estrutura do banco" in capsys.readouterr().out  # ponto de entrada criou as tabelas no banco novo
    assert run("services", "add", "acronis", "--url", "https://x.example.com", "--class", "acronis") == 1
    assert "Já existe um serviço com o slug 'acronis'" in capsys.readouterr().err
    assert run("services", "add", "zabbix", "--url", "https://z.example.com", "--class", "zabix") == 1
    assert run("services", "add", "zabbix", "--url", "nao-e-url", "--class", "zabbix") == 1

    assert run("services", "update", "acronis", "--set", "login_timeout=60", "--unset", "mfa") == 0
    out = capsys.readouterr().out
    assert '"login_timeout": 60' in out and "mfa" not in out
    assert run("services", "list") == 0
    assert "https://br02-cloud.acronis.com" in capsys.readouterr().out


@pytestmark_mysql
def test_customers_and_links_with_encrypted_mfa(project, monkeypatch, capsys):
    root, database, store = project
    run("services", "add", "acronis", "--url", "https://br02-cloud.acronis.com", "--class", "acronis")
    assert run("customers", "add", "MERCOS", "--desk-manager-id", "DM-1") == 0
    assert run("customers", "add", "Outro", "--desk-manager-id", "DM-1") == 1  # id do Desk Manager é único
    assert "Já existe um cliente com o id do Desk Manager" in capsys.readouterr().err

    monkeypatch.setattr("getpass.getpass", lambda prompt="": "não é base32!")
    assert run("customers", "link", "mercos", "acronis", "--mfa") == 1  # chave inválida: nada gravado
    monkeypatch.setattr("getpass.getpass", lambda prompt="": TOTP.lower())
    assert run("customers", "link", "DM-1", "acronis", "--mfa") == 0  # pelo id do Desk Manager
    out = capsys.readouterr().out
    assert "vínculo criado" in out and "criptografada" in out

    conn = db.connect(database, store)
    try:
        token = repository.mfa_token(conn, "MERCOS", "acronis")
        with conn.cursor() as cur:
            cur.execute("SELECT mfa_secret_encrypted FROM customer_services")
            stored = cur.fetchone()[0]
    finally:
        conn.close()
    assert TOTP not in stored and crypto.decrypt_secret(token, crypto.load_key(store)).reveal() == TOTP

    assert run("customers", "list") == 0
    assert "acronis (MFA própria)" in capsys.readouterr().out
    assert run("customers", "link", "MERCOS", "acronis") == 0  # sem --mfa: mantém a chave
    assert run("customers", "show", "MERCOS") == 0
    assert "própria do cliente" in capsys.readouterr().out
    assert run("customers", "link", "MERCOS", "acronis", "--clear-mfa") == 0
    assert run("customers", "show", "MERCOS") == 0
    out = capsys.readouterr().out
    assert "a da conta de parceiro" in out and "própria do cliente" not in out

    audit = (root / "auditoria.jsonl").read_text(encoding="utf-8")
    assert TOTP not in audit and TOTP.lower() not in audit and token not in audit


@pytestmark_mysql
def test_removals_and_ambiguous_names(project, monkeypatch, capsys):
    run("services", "add", "acronis", "--url", "https://br02-cloud.acronis.com", "--class", "acronis")
    run("customers", "add", "MERCOS")
    run("customers", "add", "Mercos")  # mesmo nome: permitido, mas referência por nome fica ambígua
    capsys.readouterr()
    assert run("customers", "show", "mercos") == 1
    assert "Há 2 clientes chamados 'mercos'" in capsys.readouterr().err
    assert run("customers", "link", "1", "acronis") == 0

    assert run("services", "remove", "acronis") == 1  # em uso
    assert "vinculado a 1 cliente(s)" in capsys.readouterr().err
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    assert run("customers", "remove", "1") == 0
    assert "Nada foi removido" in capsys.readouterr().out
    assert run("customers", "remove", "1", "--yes") == 0  # leva o vínculo junto
    assert run("services", "remove", "acronis") == 0
    assert run("customers", "unlink", "2", "acronis") == 1  # serviço não existe mais


def test_commands_without_database_section(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    assert run("customers", "list") == 1
    assert "seção 'database'" in capsys.readouterr().err


@pytestmark_mysql
def test_partner_account_mfa_external_name_and_credentials(project, monkeypatch, capsys):
    root, database, store = project
    run("services", "add", "acronis", "--url", "https://br02-cloud.acronis.com", "--class", "acronis")
    run("customers", "add", "Passebus")
    secrets = iter(["SENHAPARCEIRO", "SENHAPARCEIRO"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(secrets))
    assert run("services", "set-credentials", "acronis", "--username", "parceiro@contego.com.br") == 0
    assert store.get("acronis").username == "parceiro@contego.com.br"
    assert run("services", "set-credentials", "inexistente", "--username", "x") == 1

    monkeypatch.setattr("getpass.getpass", lambda prompt="": TOTP)
    assert run("services", "update", "acronis", "--mfa") == 0  # chave da conta de parceiro
    assert run("customers", "link", "Passebus", "acronis", "--external-name", "PASSEBUS Transportes") == 0
    out = capsys.readouterr().out
    assert "nome na plataforma: PASSEBUS Transportes" in out
    assert run("services", "list") == 0
    row = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("1 "))
    assert "cofre" in row and "sim" in row  # login no cofre e MFA da conta de parceiro

    conn = db.connect(database, store)
    try:
        key = crypto.load_key(store)
        # sem chave própria, vale a da conta de parceiro
        assert crypto.decrypt_secret(repository.mfa_token(conn, "Passebus", "acronis"), key).reveal() == TOTP
        assert repository.find_customer(conn, "Passebus").name_on("acronis") == "PASSEBUS Transportes"
    finally:
        conn.close()

    other = "MFZWIZLSMVZWKY3SMV2A"
    monkeypatch.setattr("getpass.getpass", lambda prompt="": other)
    assert run("customers", "link", "Passebus", "acronis", "--mfa") == 0  # chave própria do cliente: tem prioridade
    assert run("customers", "show", "Passebus") == 0
    assert "própria do cliente" in capsys.readouterr().out
    assert run("customers", "link", "Passebus", "acronis", "--external-name", "") == 0  # volta ao nome do cadastro
    conn = db.connect(database, store)
    try:
        assert crypto.decrypt_secret(repository.mfa_token(conn, "Passebus", "acronis"), key).reveal() == other
        assert repository.find_customer(conn, "Passebus").name_on("acronis") == "Passebus"
    finally:
        conn.close()
    audit = (root / "auditoria.jsonl").read_text(encoding="utf-8")
    assert TOTP not in audit and other not in audit and "SENHAPARCEIRO" not in audit


@pytestmark_mysql
def test_old_database_receives_new_columns(project, capsys):
    root, database, store = project
    from jervis.db.schema import TABLES
    old = dict(TABLES)
    # tabelas como na 1ª versão: sem service.mfa_secret_encrypted e sem customer_services.external_name
    old_service = "\n".join(line for line in old["service"].splitlines() if not line.strip().startswith("mfa_secret_encrypted"))
    old_links = "\n".join(line for line in old["customer_services"].splitlines() if not line.strip().startswith("external_name"))
    conn = db.connect(database, store, database=False)
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE `{database.name}`")
        cur.execute(f"USE `{database.name}`")
        for ddl in (old["customers"], old_service, old_links):
            cur.execute(ddl)
        cur.execute("INSERT INTO customers (name) VALUES ('Já existia')")
    conn.commit()
    conn.close()

    assert db.ensure_schema(database, store) == ["service.mfa_secret_encrypted", "customer_services.external_name"]
    assert db.ensure_schema(database, store) == []
    assert db.table_status(database, store)["customers"] == 1  # nada foi apagado

import pytest

from jervis import cli
from jervis.config import load_config
from jervis.credentials import CredentialStore


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # logs/ vão para o diretório temporário
    path = tmp_path / "platforms.yaml"
    assert cli.main(["-c", str(path), "init"]) == 0
    return path


def run(config_path, *args):
    return cli.main(["-c", str(config_path), *args])


def test_admin_configures_platform(config_path, capsys):
    assert run(config_path, "platforms", "set-url", "zabbix", "https://zabbix.empresa.com/index.php") == 0
    assert run(config_path, "platforms", "enable", "zabbix") == 0
    assert run(config_path, "platforms", "add", "zabbix_hml", "--kind", "zabbix", "--url", "https://z-hml.local", "--environment", "homologacao") == 0
    assert run(config_path, "platforms", "set", "zabbix_hml", "--login-timeout", "45", "--mfa", "prompt") == 0

    config = load_config(config_path)
    assert config.platforms["zabbix"].enabled
    assert config.platforms["zabbix"].url == "https://zabbix.empresa.com/index.php"
    assert config.platforms["zabbix_hml"].environment == "homologacao"
    assert config.platforms["zabbix_hml"].login_timeout == 45

    assert run(config_path, "platforms", "disable", "zabbix") == 0
    assert not load_config(config_path).platforms["zabbix"].enabled


def test_cannot_enable_without_url(config_path, capsys):
    assert run(config_path, "platforms", "enable", "acronis") == 1
    assert "Defina a URL" in capsys.readouterr().err


def test_invalid_url_rejected(config_path, capsys):
    assert run(config_path, "platforms", "set-url", "zabbix", "zabbix.local") == 1
    assert "URL inválida" in capsys.readouterr().err


def test_operator_lists_platforms_with_credential_status(config_path, capsys):
    CredentialStore().set("sophos", "op@empresa.com", "segredo-lista", "JBSWY3DPEHPK3PXP")
    capsys.readouterr()
    assert run(config_path, "platforms", "list") == 0
    out = capsys.readouterr().out
    assert "sophos" in out and "cofre +TOTP" in out
    assert "ausente" in out  # acronis/zabbix sem credenciais
    assert "0 de 3 plataforma(s) ativa(s)" in out
    assert "segredo-lista" not in out


def test_credentials_set_uses_hidden_prompt(config_path, monkeypatch, capsys):
    answers = iter(["S3nh@", "S3nh@"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert run(config_path, "credentials", "set", "zabbix", "--username", "operador") == 0
    creds = CredentialStore().get("zabbix")
    assert creds.username == "operador" and creds.password.reveal() == "S3nh@"
    assert "S3nh@" not in capsys.readouterr().out


def test_credentials_set_rejects_mismatched_confirmation(config_path, monkeypatch, capsys):
    answers = iter(["a", "b"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert run(config_path, "credentials", "set", "zabbix", "--username", "operador") == 1
    assert "não conferem" in capsys.readouterr().err
    assert not CredentialStore().status("zabbix").configured


def test_credentials_for_unknown_platform_rejected(config_path, capsys):
    assert run(config_path, "credentials", "set", "zabix", "--username", "x") == 1
    assert "não cadastrada" in capsys.readouterr().err


def test_login_without_enabled_platforms(config_path, capsys):
    assert run(config_path, "login") == 1
    assert "Nenhuma plataforma ativa" in capsys.readouterr().out


def test_login_reports_missing_credentials_clearly(config_path, capsys):
    run(config_path, "platforms", "set-url", "zabbix", "https://zabbix.invalid")
    run(config_path, "platforms", "enable", "zabbix")
    capsys.readouterr()
    assert run(config_path, "login") == 1
    out = capsys.readouterr().out
    assert "[FALHA]" in out and "jervis credentials set zabbix" in out

"""Feature 9.1: comandos da CLI de ponta a ponta (cadastro, login, coleta, agendamento)."""


import pytest
import yaml

from jervis import cli
from jervis.config import load_config
from jervis.credentials import CredentialStore


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    return tmp_path


def run(*args):
    return cli.main(["-c", "platforms.yaml", *args])


def test_platform_lifecycle(project, capsys):
    assert run("platforms", "add", "zabbix_hml", "--kind", "zabbix", "--url", "http://zbx-hml.local",
               "--environment", "homologacao", "--description", "Zabbix HML", "--mfa", "prompt", "--enable") == 0
    out_err = capsys.readouterr()
    assert "cadastrada (ativa)" in out_err.out and "HTTP sem criptografia" in out_err.err
    assert run("platforms", "add", "zabbix_hml", "--kind", "zabbix", "--url", "https://x.local") == 1  # duplicada

    assert run("platforms", "set", "zabbix_hml", "--description", "Homologação") == 0
    assert run("platforms", "set", "zabbix_hml") == 1  # nada a alterar
    assert load_config("platforms.yaml").platforms["zabbix_hml"].description == "Homologação"

    CredentialStore().set("zabbix_hml", "svc", "senha-hml")
    assert run("platforms", "remove", "zabbix_hml") == 0
    assert "zabbix_hml" not in load_config("platforms.yaml").platforms
    assert not CredentialStore().status("zabbix_hml").configured  # credenciais removidas junto


def test_platforms_list_check_reachability(project, site_url, capsys):
    run("platforms", "set-url", "zabbix", f"{site_url}/login.html")
    run("platforms", "set-url", "acronis", f"{site_url}/nao-existe.html")
    run("platforms", "set-url", "sophos", "http://127.0.0.1:1/")
    capsys.readouterr()
    assert run("platforms", "list", "--check") == 0
    out = capsys.readouterr().out
    lines = {line.split()[0]: line for line in out.splitlines() if line and line.split()[0] in ("zabbix", "acronis", "sophos")}
    assert "online (HTTP 200)" in lines["zabbix"]
    assert "online (HTTP 404)" in lines["acronis"]  # servidor responde: está no ar
    assert "inacessível" in lines["sophos"]


@pytest.mark.browser
def test_login_command(project, site_url, test_driver_path, monkeypatch, capsys):
    data = yaml.safe_load((project / "platforms.yaml").read_text(encoding="utf-8"))
    data["settings"]["driver_path"] = test_driver_path
    data["platforms"]["zabbix"].update(url=f"{site_url}/login.html", enabled=True)
    (project / "platforms.yaml").write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    monkeypatch.setenv("JERVIS_ZABBIX_USERNAME", "operador")
    monkeypatch.setenv("JERVIS_ZABBIX_PASSWORD", "S3nh@-forte")
    capsys.readouterr()
    assert run("login") == 0
    assert "[OK] login realizado" in capsys.readouterr().out
    monkeypatch.setenv("JERVIS_ZABBIX_PASSWORD", "errada")
    assert run("login", "zabbix") == 1
    out = capsys.readouterr().out
    assert "[FALHA]" in out and "Usuário ou senha incorretos" in out


@pytest.mark.browser
def test_collect_and_check_commands_end_to_end(project, site_url, test_driver_path, monkeypatch, capsys):
    data = yaml.safe_load((project / "platforms.yaml").read_text(encoding="utf-8"))
    data["settings"].update(driver_path=test_driver_path, report_formats=["csv"], collect_timeout=5)
    data["platforms"]["zabbix"].update(url=f"{site_url}/login.html", enabled=True, selectors={"success": ["aside.sidebar"]},
                                       params={"hosts": {"pages": {"monitoramento": f"{site_url}/zabbix/hosts.html"}},
                                               "inventario": {"pages": {}}, "problemas": {"pages": {}},
                                               "disponibilidade": {"pages": {}}})
    (project / "platforms.yaml").write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    monkeypatch.setenv("JERVIS_ZABBIX_USERNAME", "operador")
    monkeypatch.setenv("JERVIS_ZABBIX_PASSWORD", "S3nh@-forte")

    assert run("check") == 0
    out = capsys.readouterr().out
    assert "login: OK" in out and "hosts/monitoramento: OK" in out
    assert list((project / "logs" / "verificacao").glob("zabbix-*.json"))

    assert run("collect") == 0
    assert "zabbix: [OK] hosts: 60" in capsys.readouterr().out
    assert run("status") == 0  # saúde OK depois de uma coleta bem-sucedida


def test_schedule_run_uses_schedule_settings(project, monkeypatch):
    data = yaml.safe_load((project / "platforms.yaml").read_text(encoding="utf-8"))
    data["platforms"]["zabbix"].update(url="https://z.local", enabled=True)
    data["schedules"] = {"noturna": {"frequency": "daily", "times": ["02:00"], "platforms": ["zabbix"],
                                     "retries": 2, "retry_delay_minutes": 3},
                         "desligada": {"frequency": "daily", "times": ["03:00"], "enabled": False}}
    (project / "platforms.yaml").write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    calls = []

    class FakeRunner:
        def __init__(self, config):
            self.config = config

        def run(self, platforms, origin, retries, retry_delay):
            calls.append(([p.name for p in platforms], origin, retries, retry_delay, self.config.settings.headless))
            return type("S", (), {"exit_code": 0})()

    monkeypatch.setattr(cli, "Runner", FakeRunner)
    assert run("schedule", "run", "noturna") == 0
    assert calls == [(["zabbix"], "agendamento:noturna", 2, 180, True)]
    assert run("schedule", "run", "desligada") == 0 and len(calls) == 1  # desativado: não executa
    assert run("schedule", "run", "inexistente") == 1


@pytest.mark.browser
def test_screenshot_saved_on_login_failure(project, site_url, driver_factory):
    from jervis.collection import run_collection
    from jervis.config import PlatformConfig, Settings

    store = CredentialStore(environ={})
    store.set("zabbix", "operador", "senha-errada")
    shots = project / "capturas"
    platform = PlatformConfig(name="zabbix", kind="zabbix", url=f"{site_url}/login.html", enabled=True)
    result = run_collection(platform, Settings(screenshot_on_failure=True, screenshot_dir=str(shots), login_timeout=5),
                            store, driver_factory)
    assert result.status == "falha"
    [shot] = list(shots.glob("zabbix-login-*.png"))
    assert shot.stat().st_size > 1000

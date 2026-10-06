"""Feature 9.3: configuração por ambiente (base + arquivo do ambiente)."""

import subprocess

import pytest
import yaml

from jervis import cli, scheduling
from jervis.config import ScheduleConfig, load_config
from jervis.credentials import CredentialStore, service_for
from jervis.errors import ConfigError


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("JERVIS_ENV", raising=False)
    assert cli.main(["-c", "config/platforms.yaml", "init"]) == 0
    cli.main(["-c", "config/platforms.yaml", "platforms", "set-url", "zabbix", "https://zabbix.empresa.com/index.php"])
    return tmp_path


def write_overlay(project, env, data):
    path = project / "config" / f"platforms.{env}.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def test_overlay_overrides_only_what_changes(project):
    write_overlay(project, "hml", {"platforms": {"zabbix": {"url": "https://zabbix-hml.empresa.com", "enabled": True}},
                                   "settings": {"headless": False}})
    base, hml = load_config("config/platforms.yaml"), load_config("config/platforms.yaml", env="hml")
    assert base.platforms["zabbix"].url == "https://zabbix.empresa.com/index.php" and not base.platforms["zabbix"].enabled
    assert hml.platforms["zabbix"].url == "https://zabbix-hml.empresa.com" and hml.platforms["zabbix"].enabled
    assert hml.platforms["zabbix"].mfa == base.platforms["zabbix"].mfa  # herdado da base
    assert hml.settings.headless is False and hml.environment == "hml"


def test_environment_gets_separate_output_logs_and_audit(project):
    write_overlay(project, "hml", {"settings": {"audit_file": "auditoria/hml.jsonl"}})
    hml = load_config("config/platforms.yaml", env="hml").settings
    assert hml.output_dir == "output/hml"
    assert hml.log_file == "logs/hml/jervis.log" and hml.screenshot_dir == "logs/hml/screenshots"
    assert hml.audit_file == "auditoria/hml.jsonl"  # definido explicitamente no ambiente: respeitado


def test_env_from_environment_variable(project, monkeypatch):
    write_overlay(project, "dev", {})
    monkeypatch.setenv("JERVIS_ENV", "dev")
    assert load_config("config/platforms.yaml").environment == "dev"


@pytest.mark.parametrize("env, message", [("Produção", "inválido"), ("hml", "jervis --env hml init")])
def test_invalid_or_missing_environment(project, env, message):
    with pytest.raises(ConfigError, match=message):
        load_config("config/platforms.yaml", env=env)


def test_errors_point_to_both_files(project):
    write_overlay(project, "hml", {"platforms": {"zabbix": {"url": "sem-esquema"}}})
    with pytest.raises(ConfigError, match=r"platforms\.hml\.yaml"):
        load_config("config/platforms.yaml", env="hml")


def test_init_env_and_admin_changes_go_to_the_overlay(project, capsys):
    run = lambda *a: cli.main(["-c", "config/platforms.yaml", "--env", "hml", *a])  # noqa: E731
    assert run("init") == 0
    assert (project / "config" / "platforms.hml.yaml").exists()
    assert run("platforms", "set-url", "zabbix", "https://zabbix-hml.empresa.com") == 0
    assert run("platforms", "enable", "zabbix") == 0

    overlay = yaml.safe_load((project / "config" / "platforms.hml.yaml").read_text(encoding="utf-8"))
    assert overlay["platforms"] == {"zabbix": {"enabled": True, "url": "https://zabbix-hml.empresa.com"}}
    assert "output_dir" not in overlay.get("settings", {})  # caminhos derivados não são gravados
    base = load_config("config/platforms.yaml")
    assert base.platforms["zabbix"].url == "https://zabbix.empresa.com/index.php"  # base intacta
    assert not base.platforms["zabbix"].enabled

    assert run("platforms", "remove", "sophos") == 1
    assert "não podem ser removidas em um ambiente" in capsys.readouterr().err


def test_credentials_are_isolated_per_environment(project, monkeypatch):
    cli.main(["-c", "config/platforms.yaml", "--env", "hml", "init"])
    answers = iter(["senha-hml", "senha-hml"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["-c", "config/platforms.yaml", "--env", "hml", "credentials", "set", "zabbix", "--username", "svc-hml"]) == 0
    assert CredentialStore(service_for("hml"), environ={}).get("zabbix").username == "svc-hml"
    assert not CredentialStore(service_for(None), environ={}).status("zabbix").configured  # produção não vê


def test_config_show_reports_sources(project, capsys):
    write_overlay(project, "hml", {"settings": {"headless": False}})
    capsys.readouterr()
    assert cli.main(["-c", "config/platforms.yaml", "--env", "hml", "config", "show"]) == 0
    out = capsys.readouterr().out
    assert "# Ambiente: hml" in out and "platforms.hml.yaml" in out and "jervis3000-hml" in out
    assert "output_dir: output/hml" in out and "headless: false" in out


def test_scheduled_tasks_are_separated_per_environment(tmp_path):
    s = ScheduleConfig(name="diaria", frequency="daily", times=["07:00"])
    assert scheduling.task_names(s, "hml") == ["Jervis3000\\hml\\diaria"]
    wrapper = scheduling.write_wrapper(s, tmp_path / "platforms.yaml", workdir=tmp_path, env="hml")
    assert wrapper == tmp_path / "agendamentos" / "hml" / "diaria.cmd"
    text = wrapper.read_text(encoding="utf-8")
    assert "--env hml schedule run diaria" in text and "logs\\hml\\agendamento-diaria.log" in text

    out = ('"\\Jervis3000\\diaria","x","Pronto"\n"\\Jervis3000\\hml\\diaria","x","Pronto"\n'
           '"\\Jervis3000\\prod\\diaria","x","Pronto"\n')
    fake = lambda args, **kw: subprocess.CompletedProcess(args, 0, out, "")  # noqa: E731
    assert scheduling.installed_tasks(fake) == {"Jervis3000\\diaria"}
    assert scheduling.installed_tasks(fake, env="hml") == {"Jervis3000\\hml\\diaria"}

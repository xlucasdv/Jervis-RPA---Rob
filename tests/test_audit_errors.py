"""Épico 8: logs, auditoria, histórico e tratamento de erros."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import pytest

from jervis import cli
from jervis.audit import AuditLog, actor
from jervis.collectors.models import CollectionResult, Issue
from jervis.config import AppConfig, PlatformConfig, Settings
from jervis.credentials import CredentialStore
from jervis.errors import IssueCategory, JervisError
from jervis.logging_setup import setup_logging
from jervis.runner import MANIFEST, Progress, Runner, prune_runs, read_history
from jervis.security import SecretStr


# --- 8.4 trilha de auditoria ------------------------------------------------------------

def test_audit_records_actor_and_verifies_chain(tmp_path):
    trail = AuditLog(tmp_path / "auditoria.jsonl")
    first = trail.record("coleta_iniciada", execucao="r1", plataformas=["sophos"])
    trail.record("coleta_concluida", execucao="r1", status="sucesso")
    assert first["usuario"] == actor()["usuario"] and first["maquina"] == actor()["maquina"]
    assert first["hash_anterior"] == "0" * 64
    assert [e["evento"] for e in trail.read()] == ["coleta_iniciada", "coleta_concluida"]
    assert trail.verify() == (True, "Trilha íntegra: 2 evento(s) verificados.")


def test_audit_detects_tampering_and_deletion(tmp_path):
    path = tmp_path / "auditoria.jsonl"
    trail = AuditLog(path)
    for i in range(3):
        trail.record("credencial_cadastrada", plataforma=f"p{i}")
    lines = path.read_text(encoding="utf-8").splitlines()

    path.write_text("\n".join([lines[0], lines[1].replace('"p1"', '"outra"'), lines[2]]) + "\n", encoding="utf-8")
    ok, message = trail.verify()
    assert not ok and "Linha 2: conteúdo alterado" in message

    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    ok, message = trail.verify()
    assert not ok and "Linha 2: cadeia interrompida" in message


def test_audit_never_stores_secrets(tmp_path):
    secret = SecretStr("senha-de-servico-123")
    trail = AuditLog(tmp_path / "a.jsonl")
    trail.record("teste", erro=f"falhou com {secret.reveal()}")
    assert "senha-de-servico-123" not in (tmp_path / "a.jsonl").read_text(encoding="utf-8")
    assert trail.verify()[0]


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    return tmp_path


def test_admin_actions_are_audited(project, monkeypatch, capsys):
    run = lambda *a: cli.main(["-c", "platforms.yaml", *a])  # noqa: E731
    run("platforms", "set-url", "zabbix", "https://zabbix.empresa.com")
    run("platforms", "enable", "zabbix")
    answers = iter(["S3nh@-forte", "S3nh@-forte"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    run("credentials", "set", "zabbix", "--username", "svc.coleta@empresa.com")
    run("platforms", "disable", "zabbix")
    run("credentials", "delete", "zabbix")

    text = (project / "logs" / "auditoria.jsonl").read_text(encoding="utf-8")
    assert "S3nh@-forte" not in text and "svc.coleta@empresa.com" not in text
    events = [e["evento"] for e in AuditLog(project / "logs" / "auditoria.jsonl").read()]
    assert events == ["plataforma_url_alterada", "plataforma_ativada", "credencial_cadastrada",
                      "plataforma_desativada", "credencial_removida"]
    entry = AuditLog(project / "logs" / "auditoria.jsonl").read()[2]
    assert entry["detalhes"] == {"plataforma": "zabbix", "usuario": "sv***@empresa.com", "totp": False}

    capsys.readouterr()
    assert run("audit", "--event", "credencial") == 0
    out = capsys.readouterr().out
    assert "credencial_cadastrada" in out and "credencial_removida" in out and "plataforma_ativada" not in out
    assert run("audit", "--verify") == 0 and "[OK]" in capsys.readouterr().out


def test_cli_audit_verify_fails_on_tampering(project, capsys):
    cli.main(["-c", "platforms.yaml", "platforms", "set-url", "zabbix", "https://a.local"])
    cli.main(["-c", "platforms.yaml", "platforms", "set-url", "zabbix", "https://b.local"])
    path = project / "logs" / "auditoria.jsonl"
    path.write_text(path.read_text(encoding="utf-8").replace("https://b.local", "https://c.local"), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "audit", "--verify"]) == 1
    assert "[ALTERADA]" in capsys.readouterr().out


# --- execuções: auditoria, completude, falhas ---------------------------------------------

def result(platform, devices=10, issues=()):
    r = CollectionResult(platform=platform, kind="sophos")
    r.datasets = {"dispositivos": [{"nome": f"PC-{i}", "status_agente": "Ativo", "situacao_protecao": "Protegido",
                                    "origem": "computador"} for i in range(devices)]}
    r.issues = list(issues)
    r.finished_at = r.started_at
    return r


@pytest.fixture
def config(tmp_path):
    settings = Settings(output_dir=str(tmp_path / "output"), report_formats=["csv"],
                        audit_file=str(tmp_path / "logs" / "auditoria.jsonl"))
    return AppConfig(settings=settings, platforms={
        "sophos": PlatformConfig(name="sophos", kind="sophos", url="https://s.local", enabled=True)})


def run_with(config, *results, store=None, formats=None):
    queue = list(results)

    def collect(platform, settings, store, only=None, progress=None):
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    lines = []
    runner = Runner(config, store=store or CredentialStore(environ={}), emit=Progress(lines.append), collect=collect)
    return runner.run([config.platforms["sophos"]], formats=formats), lines


def test_run_audit_and_manifest_identify_who_and_which_account(config):
    store = CredentialStore(environ={})
    store.set("sophos", "coleta.ti@empresa.com", "S3nh@-forte")
    summary, lines = run_with(config, result("sophos"), store=store)
    assert summary.manifest["usuario"] == actor()["usuario"] and summary.manifest["maquina"] == actor()["maquina"]
    assert f"por {actor()['usuario']} em {actor()['maquina']}" in lines[0]
    started, finished = AuditLog(config.settings.audit_file).read()
    assert started["evento"] == "coleta_iniciada" and started["detalhes"]["plataformas"] == ["sophos"]
    assert started["detalhes"]["contas"] == {"sophos": {"usuario": "co***@empresa.com", "credencial": "keyring"}}
    assert finished["evento"] == "coleta_concluida" and finished["detalhes"]["plataformas"] == {"sophos": "sucesso"}
    assert read_history(Path(config.settings.output_dir))[0]["usuario"] == actor()["usuario"]


@pytest.mark.parametrize("devices_now, expect_warning", [(10, False), (6, False), (3, True), (0, True)])
def test_incomplete_data_detected_against_last_successful_run(config, devices_now, expect_warning):
    run_with(config, result("sophos", devices=10))
    summary, _ = run_with(config, result("sophos", devices=devices_now))
    saved = json.loads((summary.run_dir / "sophos.json").read_text(encoding="utf-8"))
    warnings = [i for i in saved["issues"] if i["category"] == "dados_incompletos"]
    assert bool(warnings) == expect_warning
    if expect_warning:
        assert warnings[0]["severity"] == "aviso" and "última coleta bem-sucedida (10)" in warnings[0]["message"]
        assert summary.manifest["plataformas"]["sophos"]["avisos"]  # visível em jervis runs / runs show
        assert summary.status == "sucesso"  # aviso: não é falha de coleta, mas aparece no consolidado como atenção
        consolidated = json.loads((summary.run_dir / "consolidado.json").read_text(encoding="utf-8"))
        assert any(r["status"] == "dados_incompletos" and r["classificacao"] == "atencao" for r in consolidated["registros"])


def test_drop_explained_by_page_error_is_not_flagged_again(config):
    run_with(config, result("sophos", devices=10))
    failed = result("sophos", devices=0, issues=[Issue("dispositivos/computador", IssueCategory.UI_CHANGED, "Tabela não encontrada")])
    summary, _ = run_with(config, failed)
    saved = json.loads((summary.run_dir / "sophos.json").read_text(encoding="utf-8"))
    assert [i["category"] for i in saved["issues"]] == ["interface_alterada"]


def test_report_failure_is_recorded(config, tmp_path):
    config.settings.driver_path = str(tmp_path / "nao-existe.exe")
    summary, lines = run_with(config, result("sophos"), formats=["pdf", "csv"])
    assert summary.status == "sucesso" and summary.exit_code == 2  # coleta ok, mas o relatório pedido não saiu
    assert "Driver não encontrado" in summary.manifest["falhas_relatorio"]["pdf"]
    assert any("Relatório PDF: não gerado" in line for line in lines)
    assert AuditLog(config.settings.audit_file).read()[-1]["detalhes"]["falhas_relatorio"]["pdf"]


def test_unexpected_error_closes_the_run_instead_of_leaving_it_running(config):
    with pytest.raises(JervisError, match="Erro inesperado"):
        run_with(config, RuntimeError("falha de programação"))
    [entry] = read_history(Path(config.settings.output_dir))
    assert entry["estado"] == "erro" and "RuntimeError: falha de programação" in entry["erro"]
    run_dir = Path(config.settings.output_dir) / entry["id"]
    assert json.loads((run_dir / MANIFEST).read_text(encoding="utf-8"))["estado"] == "erro"
    assert AuditLog(config.settings.audit_file).read()[-1]["evento"] == "coleta_erro"


# --- 8.1 logs ---------------------------------------------------------------------------

def test_log_lines_carry_run_id_and_steps(config, tmp_path):
    log_file = tmp_path / "logs" / "jervis.log"
    setup_logging(str(log_file))
    try:
        summary, _ = run_with(config, result("sophos"))
    finally:
        for handler in list(logging.getLogger().handlers):
            handler.close()
            logging.getLogger().removeHandler(handler)
    text = log_file.read_text(encoding="utf-8")
    run_id = summary.run_dir.name
    assert f"[{run_id}] jervis.runner: Execução {run_id} iniciada" in text
    assert f"[{run_id}] jervis.runner: sophos: [OK] dispositivos: 10" in text
    assert f"[{run_id}] jervis.runner: Execução {run_id} concluída" in text


# --- 8.3 histórico e retenção --------------------------------------------------------------

def test_prune_removes_only_old_run_folders(tmp_path):
    output = tmp_path / "output"
    for name in ("20260601-070000", "20260901-070000", "20261005-070000", "outra-pasta"):
        (output / name).mkdir(parents=True)
    keep = output / "20260601-070000"
    removed = prune_runs(output, 30, keep=keep, now=datetime(2026, 10, 6))
    assert removed == ["20260901-070000"]
    assert sorted(p.name for p in output.iterdir()) == ["20260601-070000", "20261005-070000", "outra-pasta"]
    assert prune_runs(output, 0) == []


def test_pruned_run_still_visible_in_history(config, project, capsys):
    os.chdir(project)
    summary, _ = run_with(config, result("sophos"))
    import shutil

    shutil.rmtree(summary.run_dir)
    (project / "platforms.yaml").write_text(
        (project / "platforms.yaml").read_text(encoding="utf-8").replace("output_dir: output", f"output_dir: '{config.settings.output_dir}'"),
        encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "runs", "show", summary.run_dir.name]) == 0
    out = capsys.readouterr().out
    assert "removida pela retenção" in out and "sophos: [OK]" in out

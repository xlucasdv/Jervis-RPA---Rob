import json
import re

import pytest

from jervis import cli
from jervis.collection import failed_stages, merge_retry
from jervis.collectors.models import CollectionResult, Issue
from jervis.config import AppConfig, PlatformConfig, Settings
from jervis.errors import IssueCategory
from jervis.runner import LOCK, MANIFEST, RUN_LOG, Progress, RunInProgressError, RunLock, Runner, read_history


def ok(platform, kind="sophos"):
    r = CollectionResult(platform=platform, kind=kind, environment="producao")
    r.datasets = {"dispositivos": [{"nome": "PC-1", "status_agente": "Ativo", "situacao_protecao": "Protegido",
                                    "ultima_comunicacao_iso": None, "origem": "computador"}],
                  "alertas": [{"tipo": "Malware", "severidade": "alta", "dispositivo": "PC-1", "situacao": "Open",
                               "data_hora_iso": None, "origem": "alerta"}]}
    r.finished_at = r.started_at
    return r


def auth_failure(platform, kind="sophos"):
    r = CollectionResult(platform=platform, kind=kind)
    r.issues = [Issue("autenticacao", IssueCategory.AUTHENTICATION, "Acesso negado")]
    r.finished_at = r.started_at
    return r


def page_failure(platform):
    r = ok(platform)
    r.datasets["alertas"] = []
    r.issues = [Issue("alertas/alerta", IssueCategory.UI_CHANGED, "Tabela não encontrada")]
    return r


class ScriptedCollect:
    """Coleta falsa: devolve, a cada chamada da plataforma, o próximo resultado do roteiro."""

    def __init__(self, script):
        self.script = {name: list(results) for name, results in script.items()}
        self.calls = []

    def __call__(self, platform, settings, store, only=None, progress=None):
        self.calls.append((platform.name, only))
        if progress:
            progress("autenticando...")
        return self.script[platform.name].pop(0)


@pytest.fixture
def config(tmp_path):
    platforms = {
        name: PlatformConfig(name=name, kind="sophos", url=f"https://{name}.local", enabled=True)
        for name in ("sophos", "sophos_b")
    }
    settings = Settings(output_dir=str(tmp_path / "output"), report_formats=["csv"], audit_file=str(tmp_path / "logs" / "auditoria.jsonl"))
    return AppConfig(settings=settings, platforms=platforms)


def runner(config, script, lines=None, sleeps=None):
    collect = ScriptedCollect(script)
    out = lines if lines is not None else []
    r = Runner(config, store=object(), emit=Progress(out.append), collect=collect,
               sleep=(sleeps.append if sleeps is not None else lambda s: None))
    return r, collect


# --- 7.1 / 7.3 execução e acompanhamento -----------------------------------------------

def test_manual_run_records_progress_manifest_and_history(config):
    lines = []
    r, _ = runner(config, {"sophos": [ok("sophos")], "sophos_b": [ok("sophos_b")]}, lines)
    summary = r.run(list(config.platforms.values()))
    assert summary.status == "sucesso" and summary.exit_code == 0

    assert all(re.match(r"\[\d{2}:\d{2}:\d{2}\] ", line) for line in lines)  # progresso com horário
    text = "\n".join(lines)
    assert "sophos (1/2): iniciando coleta" in text and "· sophos: autenticando..." in text
    assert "sophos: [OK] dispositivos: 1 | alertas: 1" in text and "Consolidado:" in text

    run_dir = summary.run_dir
    manifest = json.loads((run_dir / MANIFEST).read_text(encoding="utf-8"))
    assert manifest["estado"] == "concluida" and manifest["status"] == "sucesso" and manifest["origem"] == "manual"
    assert manifest["plataformas"]["sophos"]["contagens"] == {"dispositivos": 1, "alertas": 1}
    assert manifest["consolidado"] and "consolidado.csv" in manifest["relatorios"]
    assert (run_dir / RUN_LOG).read_text(encoding="utf-8").splitlines() == lines  # mesmo progresso no arquivo
    [entry] = read_history(run_dir.parent)
    assert entry["id"] == run_dir.name and entry["status"] == "sucesso" and "pid" not in entry


def test_run_status_is_partial_when_a_platform_fails(config):
    r, _ = runner(config, {"sophos": [ok("sophos")], "sophos_b": [auth_failure("sophos_b")]})
    summary = r.run(list(config.platforms.values()))
    assert summary.status == "parcial" and summary.exit_code == 2
    assert summary.manifest["plataformas"]["sophos_b"]["falhas"] == ["[autenticacao] autenticacao: Acesso negado"]


def test_only_one_run_at_a_time(config, tmp_path):
    with RunLock(tmp_path / "output" / LOCK):
        r, collect = runner(config, {"sophos": [ok("sophos")]})
        with pytest.raises(RunInProgressError, match="em andamento"):
            r.run([config.platforms["sophos"]])
        assert collect.calls == []
    r.run([config.platforms["sophos"]])  # trava liberada


# --- 7.4 reprocessamento ------------------------------------------------------------------

def test_automatic_retry_of_whole_platform(config):
    sleeps, lines = [], []
    r, collect = runner(config, {"sophos": [auth_failure("sophos"), ok("sophos")]}, lines, sleeps)
    summary = r.run([config.platforms["sophos"]], retries=2, retry_delay=600)
    assert summary.status == "sucesso"
    assert collect.calls == [("sophos", None), ("sophos", None)]  # parou de tentar após o sucesso
    assert sleeps == [600]
    assert summary.manifest["plataformas"]["sophos"]["tentativas"] == 2
    assert any("Reprocessamento automático 1/2 de sophos em 10 min" in line for line in lines)


def test_retry_repeats_only_the_failed_page_and_merges(config):
    retry_result = ok("sophos")
    retry_result.datasets = {"alertas": ok("sophos").datasets["alertas"]}
    r, collect = runner(config, {"sophos": [page_failure("sophos"), retry_result]})
    summary = r.run([config.platforms["sophos"]], retries=1)
    assert collect.calls == [("sophos", None), ("sophos", {"alertas/alerta"})]
    saved = json.loads((summary.run_dir / "sophos.json").read_text(encoding="utf-8"))
    assert saved["counts"] == {"dispositivos": 1, "alertas": 1}  # dispositivos mantidos da 1ª tentativa
    assert saved["issues"] == [] and saved["status"] == "sucesso" and saved["attempts"] == 2


def test_manual_retry_of_saved_run(config):
    r, _ = runner(config, {"sophos": [ok("sophos")], "sophos_b": [auth_failure("sophos_b")]})
    first = r.run(list(config.platforms.values()))
    lines = []
    r2, collect = runner(config, {"sophos_b": [ok("sophos_b")]}, lines)
    summary = r2.retry(first.run_dir)
    assert collect.calls == [("sophos_b", None)]  # só a plataforma que falhou
    assert summary.status == "sucesso"
    assert any("sophos: nada a reprocessar (sem falhas)" in line for line in lines)
    manifest = json.loads((first.run_dir / MANIFEST).read_text(encoding="utf-8"))
    assert manifest["reprocessamentos"][0]["plataformas"] == ["sophos_b"]
    assert manifest["duracao_s"] == first.manifest["duracao_s"]  # duração original preservada
    assert manifest["reprocessamentos"][0]["duracao_s"] is not None
    assert [e["origem"] for e in read_history(first.run_dir.parent)] == ["manual", "reprocessamento"]


def test_configuration_errors_are_not_retried(config):
    bad = CollectionResult(platform="sophos", kind="sophos")
    bad.issues = [Issue("configuracao", IssueCategory.CONFIGURATION, "Nenhuma credencial cadastrada")]
    r, collect = runner(config, {"sophos": [bad]})
    r.run([config.platforms["sophos"]], retries=3)
    assert len(collect.calls) == 1


def test_failed_stages():
    assert failed_stages(ok("x")) == set()
    assert failed_stages(auth_failure("x")) is None
    assert failed_stages(page_failure("x")) == {"alertas/alerta"}
    warning_only = ok("x")
    warning_only.issues = [Issue("alertas/alerta", IssueCategory.UI_CHANGED, "coluna ausente", severity="aviso")]
    assert failed_stages(warning_only) == set()
    assert failed_stages(page_failure("x").to_dict()) == {"alertas/alerta"}  # também a partir do JSON salvo


def test_merge_full_retry_replaces_result():
    merged = merge_retry(auth_failure("x"), ok("x"), None)
    assert merged.status == "sucesso" and merged.attempts == 2


def test_result_roundtrip_from_saved_json():
    original = page_failure("x")
    rebuilt = CollectionResult.from_dict(json.loads(json.dumps(original.to_dict())))
    assert rebuilt.to_dict() == original.to_dict()


# --- CLI ------------------------------------------------------------------------------

def test_cli_runs_lists_history_and_interrupted(config, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["-c", "platforms.yaml", "init"])
    output = tmp_path / "output"
    r, _ = runner(config, {"sophos": [ok("sophos")], "sophos_b": [auth_failure("sophos_b")]})
    done = r.run(list(config.platforms.values()))
    crashed = output / "20991231-235959"
    crashed.mkdir()
    (crashed / MANIFEST).write_text(json.dumps({"id": crashed.name, "origem": "agendamento:diaria", "estado": "em_andamento",
                                                "inicio": "2026-10-06T07:00:00-03:00", "plataformas": {}}), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "runs"]) == 0
    out = capsys.readouterr().out
    assert crashed.name in out and "INTERROMPIDA" in out
    assert done.run_dir.name in out and "PARCIAL" in out and "sophos_b:FALHA" in out

    assert cli.main(["-c", "platforms.yaml", "runs", "show", done.run_dir.name]) == 0
    out = capsys.readouterr().out
    assert "sophos_b: [FALHA]" in out and "erro: [autenticacao]" in out and "execucao.log" in out


def test_cli_schedule_list(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["-c", "platforms.yaml", "init"])
    text = (tmp_path / "platforms.yaml").read_text(encoding="utf-8").replace("    enabled: false\n    frequency: daily", "    enabled: true\n    frequency: daily")
    (tmp_path / "platforms.yaml").write_text(text, encoding="utf-8")
    monkeypatch.setattr(cli.scheduling, "installed_tasks", lambda **kwargs: set())
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "schedule", "list"]) == 0
    out = capsys.readouterr().out
    assert "diaria" in out and "diariamente às 07:00" in out and "todas as ativas" in out
    assert "jervis schedule install" in out  # ativo mas não registrado no Windows

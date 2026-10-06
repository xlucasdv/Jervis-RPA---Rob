"""Coleta da Acronis com navegador real contra o console falso de tests/fixtures/site/acronis."""

import pytest

from jervis.collectors.acronis import AcronisCollector
from jervis.collectors.models import CollectionResult
from jervis.config import PlatformConfig, Settings

pytestmark = pytest.mark.browser

PAGES = {
    "dispositivos": {"pages": {"dispositivo": "/acronis/console.html#/devices"}},
    "tarefas": {"pages": {"atividade": "/acronis/console.html#/activities"}},
}


@pytest.fixture(scope="module")
def result(driver, site_url):
    platform = PlatformConfig(
        name="acronis", kind="acronis", url=f"{site_url}/acronis/", enabled=True,
        params={"timeout": 5, "retries": 0, **PAGES},
    )
    collector = AcronisCollector(platform, Settings(), poll_interval=0.1, settle=0.5)
    result = CollectionResult(platform="acronis", kind="acronis")
    collector.collect(driver, result, base_url=site_url)
    return result


def by(rows, key):
    return {row[key]: row for row in rows}


def test_collects_without_errors(result):
    assert result.issues == []
    assert result.counts() == {"dispositivos": 6, "tarefas": 12}  # tarefas em 2 páginas


def test_spa_route_change_does_not_reuse_previous_table(result):
    # Sem o recarregamento entre rotas, a tabela de dispositivos (que também tem "Status")
    # seria lida de novo como se fosse a de tarefas.
    tasks = result.datasets["tarefas"]
    assert all(row["dispositivo"] and row["nome_tarefa"] for row in tasks)  # colunas que só existem em atividades
    assert {"PC-OK-01", "PC-OK-06"} <= set(by(tasks, "dispositivo"))


def test_device_protection_status_and_highlights(result):
    devices = by(result.datasets["dispositivos"], "nome")
    assert {name: d["situacao_backup"] for name, d in devices.items()} == {
        "SRV-DC01": "ok",
        "SRV-FS01": "desatualizado",
        "PC-FIN-01": "falha",
        "PC-RH-02": "sem_protecao",
        "PC-NEW-03": "nunca_executado",
        "VM-APP-04": "com_avisos",
    }
    assert devices["SRV-DC01"]["plano_protecao"] == "Diário"
    assert devices["SRV-DC01"]["ultimo_backup_iso"] is not None  # formato americano com AM/PM interpretado
    assert "5 dias" in devices["SRV-FS01"]["motivo"]


def test_backup_tasks_fields_and_highlights(result):
    tasks = by(result.datasets["tarefas"], "dispositivo")
    failed = tasks["PC-FIN-01"]
    assert failed["situacao_backup"] == "falha"
    assert failed["mensagem_erro"] == "Acesso negado ao volume C:"
    assert "Acesso negado ao volume C:" in failed["motivo"]

    ok = tasks["PC-OK-01"]
    assert ok["nome_tarefa"] == "Backup diário" and ok["status_backup"] == "Sucesso"
    assert ok["duracao_segundos"] == 180 and ok["tamanho_bytes"] == 100 * 1024**2
    assert ok["ultima_execucao_iso"] is not None and ok["situacao_backup"] == "ok"

    assert tasks["VM-APP-04"]["situacao_backup"] == "com_avisos"  # "há 3 horas": recente
    assert tasks["SRV-FS01"]["situacao_backup"] == "desatualizado"
    assert tasks["PC-NEW-03"]["situacao_backup"] == "em_execucao"


def test_summary(result):
    assert result.summary["destaques"] == {
        "dispositivos": {"desatualizado": 1, "falha": 1, "sem_protecao": 1, "nunca_executado": 1, "com_avisos": 1},
        "tarefas": {"desatualizado": 1, "falha": 1, "com_avisos": 1, "incompleto": 1, "em_execucao": 1},
    }

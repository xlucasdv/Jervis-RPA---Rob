from datetime import datetime

import pytest

from jervis.collectors import build_collector
from jervis.collectors.acronis import AcronisCollector, classify_status
from jervis.collectors.models import CollectionResult
from jervis.config import PlatformConfig, Settings
from jervis.errors import ConfigError

NOW = datetime(2026, 10, 6, 12, 0)


def collector(params=None):
    platform = PlatformConfig(name="acronis", kind="acronis", url="https://eu2-cloud.acronis.com/login", enabled=True, params=params or {})
    return AcronisCollector(platform, Settings(), now=lambda: NOW)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Succeeded", "ok"), ("Sucesso", "ok"), ("OK", "ok"), ("Concluído", "ok"),
        ("Succeeded with warnings", "com_avisos"), ("Concluído com avisos", "com_avisos"), ("Warning", "com_avisos"),
        ("Failed", "falha"), ("Falhou", "falha"), ("Error", "falha"), ("Critical", "falha"),
        ("Canceled", "incompleto"), ("Interrompido", "incompleto"), ("Concluído parcialmente", "incompleto"),
        ("Running", "em_execucao"), ("Em andamento", "em_execucao"),
        ("Not protected", "sem_protecao"), ("Não protegido", "sem_protecao"),
        ("Concluído sem erros", "ok"), ("Completed with no errors", "ok"),
        ("Pendente de revisão", "desconhecido"), (None, "desconhecido"),
    ],
)
def test_classify_status(text, expected):
    assert classify_status(text) == expected


def task(**fields):
    return collector()._normalize_task({"nome_tarefa": "Backup diário", "dispositivo": "SRV-01", **fields})


def device(**fields):
    return collector()._normalize_device({"nome": "SRV-01", "plano_protecao": "Diário", **fields})


def test_failed_task_includes_error_message():
    row = task(status_backup="Falhou", ultima_execucao="06/10/2026 10:00", mensagem_erro="Acesso negado")
    assert row["situacao_backup"] == "falha"
    assert "Acesso negado" in row["motivo"]


def test_outdated_task_beats_warnings_and_reports_age():
    row = task(status_backup="Succeeded with warnings", ultima_execucao="01/10/2026 12:00")
    assert row["situacao_backup"] == "desatualizado"
    assert row["motivo"] == "Último backup há 5 dias (limite: 26 horas)."


def test_successful_recent_task_is_ok_and_values_are_parsed():
    row = task(status_backup="Sucesso", ultima_execucao="há 3 horas", duracao="1 h 5 min", tamanho="1,5 GB")
    assert (row["situacao_backup"], row["motivo"]) == ("ok", None)
    assert row["ultima_execucao_iso"].startswith("2026-10-06T09:00")
    assert row["duracao_segundos"] == 3900 and row["tamanho_bytes"] == 1610612736


def test_running_task_is_not_flagged_as_outdated():
    assert task(status_backup="Em andamento", ultima_execucao="01/10/2026 12:00")["situacao_backup"] == "em_execucao"


def test_max_age_is_configurable():
    platform_collector = collector({"max_age_hours": 200})
    row = platform_collector._normalize_task({"status_backup": "Sucesso", "ultima_execucao": "01/10/2026 12:00"})
    assert row["situacao_backup"] == "ok"


@pytest.mark.parametrize(
    "fields, expected",
    [
        ({"status_protecao": "Not protected", "ultimo_backup": "Never"}, "sem_protecao"),
        ({"status_protecao": "Error", "ultimo_backup": "06/10/2026 10:00"}, "falha"),
        ({"status_protecao": "OK", "ultimo_backup": "Never"}, "nunca_executado"),
        ({"status_protecao": "Warning", "ultimo_backup": "01/10/2026 12:00"}, "desatualizado"),
        ({"status_protecao": "Warning", "ultimo_backup": "06/10/2026 10:00"}, "com_avisos"),
        ({"status_protecao": "OK", "ultimo_backup": "06/10/2026 10:00"}, "ok"),
    ],
)
def test_device_classification(fields, expected):
    assert device(**fields)["situacao_backup"] == expected


def test_summary_counts_only_problems():
    c = collector()
    result = CollectionResult(platform="acronis", kind="acronis")
    result.datasets = {
        "dispositivos": [{"situacao_backup": "ok"}, {"situacao_backup": "sem_protecao"}],
        "tarefas": [{"situacao_backup": "falha"}, {"situacao_backup": "falha"}, {"situacao_backup": "desatualizado"}],
    }
    c.summarize(result)
    assert result.summary == {
        "limite_desatualizado_horas": 26.0,
        "destaques": {"dispositivos": {"sem_protecao": 1}, "tarefas": {"falha": 2, "desatualizado": 1}},
    }


@pytest.mark.parametrize("params", [{"max_age_hours": 0}, {"max_age_hours": "1d"}, {"date_order": "ymd"}, {"max_age": 5}])
def test_invalid_params(params):
    with pytest.raises(ConfigError):
        collector(params)


def test_registered_collector():
    platform = PlatformConfig(name="acronis", kind="acronis", url="https://x.acronis.com", enabled=True)
    assert isinstance(build_collector(platform, Settings()), AcronisCollector)

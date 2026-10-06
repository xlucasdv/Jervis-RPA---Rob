import json

import pytest

from jervis.collection import save_result
from jervis.collectors import build_collector
from jervis.collectors.models import WARNING, CollectionResult, Issue
from jervis.collectors.sophos import ALERT_COLUMNS, DEVICE_COLUMNS, SophosCollector, normalize_severity
from jervis.collectors.table import map_columns, normalize_label
from jervis.config import PlatformConfig, Settings
from jervis.errors import ConfigError, IssueCategory
from jervis.security import SecretStr


def sophos(params=None, kind="sophos"):
    return PlatformConfig(name="sophos", kind=kind, url="https://central.sophos.com/manage", enabled=True, params=params or {})


def test_normalize_label_removes_accents_and_sort_arrows():
    assert normalize_label("Última atividade ▲") == "ultima atividade"
    assert normalize_label("Quem/o quê") == "quem o que"


def test_device_columns_map_portuguese_and_english_headers():
    pt = ["", "Nome ▲", "SO", "Integridade", "Proteção", "Última atividade", "IP"]
    assert map_columns(pt, DEVICE_COLUMNS) == {
        "nome": 1, "sistema_operacional": 2, "status_agente": 3, "situacao_protecao": 4, "ultima_comunicacao": 5, "ip": 6,
    }
    en = ["Name", "OS", "Health", "Protection status", "Last active"]
    assert map_columns(en, DEVICE_COLUMNS) == {
        "nome": 0, "sistema_operacional": 1, "status_agente": 2, "situacao_protecao": 3, "ultima_comunicacao": 4,
    }


def test_alert_columns_prefer_type_over_description():
    assert map_columns(["Tipo", "Descrição", "Severidade", "Data/hora"], ALERT_COLUMNS)["tipo"] == 0
    mapping = map_columns(["Severity", "Date/Time", "Description", "Who/What", "Status"], ALERT_COLUMNS)
    assert mapping == {"tipo": 2, "descricao": 2, "severidade": 0, "dispositivo": 3, "data_hora": 1, "situacao": 4}


def test_column_by_position_escape_hatch():
    assert map_columns(["", "Data"], {"severidade": ("#1",)}) == {"severidade": 0}


@pytest.mark.parametrize(
    "raw, expected",
    [("High", "alta"), ("Severidade média", "media"), ("low", "baixa"), ("Critical", "critica"), ("Outra", "Outra"), (None, None)],
)
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


def test_params_override_pages_columns_and_table():
    collector = SophosCollector(sophos({
        "timeout": 10,
        "retries": 2,
        "dispositivos": {"pages": {"servidor": "/servers"}, "columns": {"status_agente": "Estado do agente"}},
        "alertas": {"table": {"next_page": "button.proxima", "max_pages": 5}},
    }), Settings())
    devices = collector.datasets["dispositivos"]
    assert dict(devices.pages) == {"servidor": "/servers"}
    assert devices.table.columns["status_agente"] == ("Estado do agente",)
    assert devices.table.columns["nome"] == DEVICE_COLUMNS["nome"]  # demais colunas mantidas
    assert collector.datasets["alertas"].table.next_page == ("button.proxima",)
    assert collector.datasets["alertas"].table.max_pages == 5
    assert (collector.timeout, collector.retries) == (10, 2)


def test_dataset_can_be_disabled_with_empty_pages():
    collector = SophosCollector(sophos({"alertas": {"pages": {}}}), Settings())
    assert dict(collector.datasets["alertas"].pages) == {}


@pytest.mark.parametrize(
    "params, message",
    [
        ({"dispositivo": {}}, "desconhecido"),
        ({"alertas": {"paginas": {}}}, "desconhecida"),
        ({"alertas": {"table": {"linhas": "tr"}}}, "desconhecida"),
        ({"alertas": {"pages": ["/x"]}}, "origem"),
        ({"timeout": 0}, "inteiro positivo"),
        ({"retries": -1}, "maior ou igual"),
    ],
)
def test_invalid_params(params, message):
    with pytest.raises(ConfigError, match=message):
        SophosCollector(sophos(params), Settings())


def test_no_collector_for_unknown_kind():
    with pytest.raises(ConfigError, match="ainda não disponível"):
        build_collector(sophos(kind="nagios"), Settings())


def test_result_status():
    result = CollectionResult(platform="sophos", kind="sophos")
    result.datasets["dispositivos"] = []
    result.add_issue(Issue("dispositivos/servidor", IssueCategory.UI_CHANGED, "coluna X ausente", severity=WARNING))
    assert result.status == "sucesso"
    result.add_issue(Issue("alertas/alerta", IssueCategory.TIMEOUT, "lento"))
    assert result.status == "falha"
    result.datasets["dispositivos"].append({"nome": "PC-1"})
    assert result.status == "parcial"


def test_saved_result_is_json_with_secrets_redacted(tmp_path):
    secret = SecretStr("vazou-no-erro-77")
    result = CollectionResult(platform="sophos", kind="sophos", environment="producao")
    result.datasets["dispositivos"] = [{"nome": "PC-1", "origem": "computador"}]
    result.add_issue(Issue("coleta", IssueCategory.UNEXPECTED, f"erro com {secret.reveal()}"))
    path = save_result(result, tmp_path / "run")
    text = path.read_text(encoding="utf-8")
    assert "vazou-no-erro-77" not in text
    data = json.loads(text)
    assert data["status"] == "parcial"
    assert data["counts"] == {"dispositivos": 1}
    assert data["issues"][0]["category"] == "inesperado"

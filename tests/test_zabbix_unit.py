from datetime import datetime

import pytest

from jervis.collectors.models import CollectionResult
from jervis.collectors.parsing import parse_datetime, parse_duration, parse_percent
from jervis.collectors.zabbix import (
    ZabbixCollector,
    availability_from,
    monitoring_from,
    normalize_severity,
    problem_state,
    split_interface,
)
from jervis.config import PlatformConfig, Settings
from jervis.errors import ConfigError

NOW = datetime(2026, 10, 6, 12, 0)


def collector(params=None):
    platform = PlatformConfig(name="zabbix", kind="zabbix", url="https://zbx.local/zabbix/index.php", enabled=True, params=params or {})
    return ZabbixCollector(platform, Settings(), now=lambda: NOW)


@pytest.mark.parametrize(
    "classes, text, expected",
    [
        ("status-green", "ZBX", "disponivel"),
        ("status-red", "ZBX", "indisponivel"),
        ("status-green status-red", "ZBX SNMP", "parcial"),
        ("status-yellow", "ZBX", "parcial"),
        ("status-grey", "ZBX", "desconhecido"),
        ("", "Indisponível", "indisponivel"),
        ("", None, "desconhecido"),
    ],
)
def test_availability_from_badges(classes, text, expected):
    assert availability_from(classes, text) == expected


@pytest.mark.parametrize(
    "text, classes, expected",
    [("High", "", "alta"), ("Desastre", "", "desastre"), ("Média", "", "media"), ("Atenção", "", "atencao"),
     ("Not classified", "", "nao_classificada"), (None, "na-bg", "nao_classificada"), ("", "disaster-bg", "desastre"),
     ("Personalizada", "", "Personalizada")],
)
def test_normalize_severity(text, classes, expected):
    assert normalize_severity(text, classes) == expected


def test_monitoring_and_problem_state():
    assert monitoring_from("Enabled") is True and monitoring_from("Desativado") is False and monitoring_from("?") is None
    assert problem_state("PROBLEM") == "ativo" and problem_state("RESOLVIDO") == "resolvido" and problem_state("") is None


@pytest.mark.parametrize(
    "text, expected",
    [("10.0.0.1:10050", ("10.0.0.1", "10050")), ("srv.local: 161", ("srv.local", "161")),
     ("[::1]:10050", ("::1", "10050")), ("10.0.0.1:10050 10.0.0.1:161", ("10.0.0.1", "10050")),
     ("10.0.0.1", ("10.0.0.1", None)), (None, (None, None))],
)
def test_split_interface(text, expected):
    assert split_interface(text) == expected


def test_zabbix_value_formats():
    assert parse_datetime("09:12:33", NOW) == datetime(2026, 10, 6, 9, 12, 33)
    assert parse_datetime("23:50:00", NOW) == datetime(2026, 10, 5, 23, 50)  # horário futuro = ontem
    assert parse_datetime("2026-10-05 22:01:10", NOW) == datetime(2026, 10, 5, 22, 1, 10)
    assert parse_duration("1M 10d") == 40 * 86400
    assert parse_duration("1y 2M 3d 4h 5m 6s") == 365 * 86400 + 60 * 86400 + 3 * 86400 + 4 * 3600 + 5 * 60 + 6
    assert parse_percent("99.8500%") == 99.85 and parse_percent("99,85 %") == 99.85 and parse_percent("n/a") is None


def test_normalize_host():
    row = collector()._normalize_host({
        "nome": "srv-001", "ip": "10.0.0.1:10050", "status_monitoramento": "Enabled",
        "disponibilidade": "ZBX SNMP", "_disponibilidade_classes": "status-green status-red",
        "grupo": None, "ultima_atualizacao": None,
    })
    assert row["ip"] == "10.0.0.1" and row["porta"] == "10050" and row["interface"] == "10.0.0.1:10050"
    assert row["disponibilidade"] == "parcial" and row["interfaces_monitoradas"] == "ZBX SNMP"
    assert row["monitorado"] is True


def test_availability_below_target():
    c = collector({"min_availability": 99.9})
    assert c._normalize_availability({"ok_pct": "99.8500%", "problema_pct": "0.1500%"})["abaixo_da_meta"] is True
    assert c._normalize_availability({"ok_pct": "100.0000%", "problema_pct": "0%"})["abaixo_da_meta"] is False
    unparsed = c._normalize_availability({"ok_pct": "n/d", "problema_pct": None})
    assert unparsed["ok_pct"] == "n/d" and unparsed["abaixo_da_meta"] is None


def test_summarize_enriches_hosts_and_counts():
    c = collector()
    result = CollectionResult(platform="zabbix", kind="zabbix")
    result.datasets = {
        "hosts": [
            {"nome": "a", "disponibilidade": "disponivel", "monitorado": True, "grupo": None, "ultima_atualizacao": None},
            {"nome": "b", "disponibilidade": "indisponivel", "monitorado": True, "grupo": None, "ultima_atualizacao": None},
            {"nome": "c", "disponibilidade": "desconhecido", "monitorado": False, "grupo": None, "ultima_atualizacao": None},
        ],
        "inventario": [{"host": "a", "grupo": "Web"}, {"host": "a", "grupo": "Linux"}],
        "itens": [{"host": "a", "ultima_verificacao": "09:00:00"}, {"host": "a", "ultima_verificacao": "11:00:00"}],
        "problemas": [
            {"host": "b", "descricao": "down", "data_hora": "10:00:00", "situacao": "ativo", "severidade": "alta"},
            {"host": "b", "descricao": "down", "data_hora": "10:00:00", "situacao": "ativo", "severidade": "alta"},
            {"host": "a", "descricao": "cpu", "data_hora": "08:00:00", "situacao": "resolvido", "severidade": "media"},
            {"host": "a", "descricao": "disk", "data_hora": "07:00:00", "situacao": "ativo", "severidade": "desastre"},
        ],
        "disponibilidade": [{"host": "b", "indicador": "down", "ok_pct": 97.5, "abaixo_da_meta": True}],
    }
    c.summarize(result)
    host_a = result.datasets["hosts"][0]
    assert host_a["grupo"] == "Linux, Web"
    assert host_a["ultima_atualizacao"] == "11:00:00" and host_a["ultima_atualizacao_iso"].startswith("2026-10-06T11:00")
    assert result.summary["destaques"] == {
        "hosts": {"indisponivel": 1, "nao_monitorado": 1},
        "problemas": {"desastre": 1, "alta": 1},  # duplicado (ativo + histórico) contado uma vez
        "disponibilidade": {"abaixo_da_meta": 1},
    }
    assert list(result.summary["destaques"]["problemas"]) == ["desastre", "alta"]  # ordem de gravidade
    assert result.summary["problemas_ativos_total"] == 2
    assert result.summary["piores_disponibilidades"] == [{"host": "b", "indicador": "down", "ok_pct": 97.5}]


@pytest.mark.parametrize("params", [{"min_availability": 0}, {"min_availability": 101}, {"min_availability": "99%"}])
def test_invalid_min_availability(params):
    with pytest.raises(ConfigError):
        collector(params)


def test_items_dataset_is_disabled_by_default():
    assert dict(collector().datasets["itens"].pages) == {}

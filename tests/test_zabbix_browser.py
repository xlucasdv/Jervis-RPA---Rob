"""Coleta do Zabbix com navegador real contra o frontend falso de tests/fixtures/site/zabbix."""

import pytest

from jervis.collectors.models import CollectionResult
from jervis.collectors.zabbix import ZabbixCollector
from jervis.config import PlatformConfig, Settings

pytestmark = pytest.mark.browser

# Caminhos relativos (sem "/" inicial), como os padrões: resolvidos a partir da URL do Zabbix.
PAGES = {
    "hosts": {"pages": {"monitoramento": "hosts.html"}},
    "inventario": {"pages": {"inventario": "inventory.html"}},
    "problemas": {"pages": {"ativo": "problems.html"}},
    "disponibilidade": {"pages": {"relatorio_7d": "availability.html"}},
    "itens": {"pages": {"dados_recentes": "latest.html"}},
}


@pytest.fixture(scope="module")
def result(driver, site_url):
    platform = PlatformConfig(
        name="zabbix", kind="zabbix", url=f"{site_url}/zabbix/index.php", enabled=True,
        params={"timeout": 5, "retries": 0, **PAGES},
    )
    collector = ZabbixCollector(platform, Settings(), poll_interval=0.1, settle=0.5)
    result = CollectionResult(platform="zabbix", kind="zabbix")
    collector.collect(driver, result, base_url=f"{site_url}/zabbix/zabbix.php?action=dashboard.view")
    return result


def by(rows, key):
    return {row[key]: row for row in rows}


def test_collects_everything_without_errors(result):
    assert result.issues == []
    assert result.counts() == {"hosts": 60, "inventario": 4, "problemas": 5, "disponibilidade": 4, "itens": 3}


def test_hosts_across_reloading_pages(result):
    hosts = by(result.datasets["hosts"], "nome")
    assert set(hosts) == {f"srv-{i:03d}" for i in range(1, 61)}  # paginação por link (recarrega a página)
    host = hosts["srv-001"]
    assert (host["ip"], host["porta"]) == ("10.0.0.1", "10050")
    assert host["status_monitoramento"] == "Enabled" and host["monitorado"] is True
    assert host["disponibilidade"] == "disponivel"


def test_availability_read_from_badge_colors(result):
    hosts = by(result.datasets["hosts"], "nome")
    assert hosts["srv-010"]["disponibilidade"] == "indisponivel"
    assert hosts["srv-007"]["disponibilidade"] == "parcial"
    assert hosts["srv-007"]["interfaces_monitoradas"] == "ZBX SNMP"
    assert hosts["srv-013"]["monitorado"] is False


def test_groups_and_last_update_filled_from_other_pages(result):
    hosts = by(result.datasets["hosts"], "nome")
    assert hosts["srv-001"]["grupo"] == "Linux servers, Web"
    assert hosts["srv-010"]["grupo"] == "Databases"
    assert hosts["srv-050"]["grupo"] is None  # sem inventário
    assert hosts["srv-001"]["ultima_atualizacao_iso"] is not None  # a mais recente entre os itens
    assert hosts["srv-002"]["ultima_atualizacao"].count("-") == 2  # item de 3 dias atrás: data completa


def test_problems_with_merged_header_and_separator_rows(result):
    problems = by(result.datasets["problemas"], "descricao")
    agent = problems["Zabbix agent is not available"]
    assert agent["host"] == "srv-010" and agent["severidade"] == "alta" and agent["situacao"] == "ativo"
    assert agent["duracao_segundos"] == 3600 and agent["data_hora_iso"] is not None
    assert problems["High CPU utilization"]["situacao"] == "resolvido"
    assert problems["Disk space is low"]["duracao_segundos"] == 40 * 86400
    assert problems["Custom check"]["severidade"] == "nao_classificada"  # só pela cor da célula


def test_availability_indicators(result):
    indicators = by(result.datasets["disponibilidade"], "host")
    assert indicators["srv-010"]["ok_pct"] == 97.5 and indicators["srv-010"]["abaixo_da_meta"] is True
    assert indicators["srv-001"]["abaixo_da_meta"] is False


def test_summary(result):
    summary = result.summary
    assert summary["destaques"] == {
        "hosts": {"indisponivel": 6, "parcial": 1, "nao_monitorado": 1},
        "problemas": {"desastre": 1, "alta": 1, "atencao": 1, "nao_classificada": 1},
        "disponibilidade": {"abaixo_da_meta": 2},
    }
    assert summary["hosts_total"] == 60 and summary["problemas_ativos_total"] == 4
    assert [w["host"] for w in summary["piores_disponibilidades"]] == ["srv-010", "srv-007"]

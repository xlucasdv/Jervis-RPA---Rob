"""Coleta da Sophos com navegador real contra o Sophos falso de tests/fixtures/site/sophos."""

import uuid
from datetime import datetime

import pytest

from jervis.collection import run_collection
from jervis.collectors.models import CollectionResult
from jervis.collectors.parsing import to_iso
from jervis.collectors.sophos import SophosCollector
from jervis.config import PlatformConfig, Settings
from jervis.credentials import CredentialStore
from jervis.errors import IssueCategory

pytestmark = pytest.mark.browser

DEFAULT_PAGES = {
    "dispositivos": {"pages": {"computador": "/sophos/computers.html", "servidor": "/sophos/servers.html"}},
    "alertas": {"pages": {"alerta": "/sophos/alerts.html"}},
}


def collect(driver, site_url, params=None, timeout=3, retries=0):
    platform = PlatformConfig(
        name="sophos", kind="sophos", url=f"{site_url}/sophos/", enabled=True,
        params={"timeout": timeout, "retries": retries, **DEFAULT_PAGES, **(params or {})},
    )
    collector = SophosCollector(platform, Settings(), poll_interval=0.1, settle=0.5)
    result = CollectionResult(platform="sophos", kind="sophos")
    collector.collect(driver, result, base_url=site_url)
    return result


def pages(**datasets):
    return {name: {"pages": p} for name, p in datasets.items()}


def test_collects_devices_across_pages_and_languages(driver, site_url):
    result = collect(driver, site_url)
    assert result.errors == []
    devices = result.datasets["dispositivos"]
    assert len(devices) == 27  # 25 computadores em 3 páginas + 2 servidores
    assert devices[0] == {
        "nome": "PC-001", "sistema_operacional": "Windows 11 Pro", "status_agente": "Inativo",
        "ultima_comunicacao": "06/10/2026 09:00", "situacao_protecao": "Desatualizada",
        "ip": "10.0.0.1", "ultimo_usuario": None, "grupo": None, "origem": "computador",
        "ultima_comunicacao_iso": to_iso(datetime(2026, 10, 6, 9, 0)),
    }
    assert [d["nome"] for d in devices[:25]] == [f"PC-{i:03d}" for i in range(1, 26)]
    server = devices[-1]
    assert server["nome"] == "SRV-FS01" and server["origem"] == "servidor"
    assert server["status_agente"] == "Bad" and server["situacao_protecao"] == "Not protected"
    assert server["ip"] is None  # coluna inexistente na tela de servidores → aviso, não erro


def test_collects_alerts_with_icon_severity(driver, site_url):
    alerts = collect(driver, site_url).datasets["alertas"]
    assert [a["severidade"] for a in alerts] == ["alta", "media", "baixa"]
    assert alerts[0] == {
        "tipo": "Malware detected: Troj/Agent-XYZ", "descricao": "Malware detected: Troj/Agent-XYZ",
        "severidade": "alta", "dispositivo": "PC-003", "data_hora": "Oct 6, 2026 8:01 AM",
        "situacao": "Open", "origem": "alerta", "data_hora_iso": to_iso(datetime(2026, 10, 6, 8, 1)),
    }


def test_extra_columns_missing_are_silent(driver, site_url):
    result = collect(driver, site_url)
    assert result.issues == []  # servidores sem IP/usuário/grupo não geram ruído


def test_missing_expected_columns_are_warnings(driver, site_url):
    result = collect(driver, site_url, pages(dispositivos={"computador": "/sophos/partial.html"}, alertas={}))
    assert result.status == "sucesso"
    [warning] = result.issues
    assert warning.severity == "aviso" and warning.category == IssueCategory.UI_CHANGED
    assert "status_agente, ultima_comunicacao, situacao_protecao" in warning.message
    assert result.datasets["dispositivos"][0]["status_agente"] is None


def test_ui_change_is_reported_and_other_pages_still_collected(driver, site_url):
    result = collect(driver, site_url, pages(
        dispositivos={"computador": "/sophos/changed.html", "servidor": "/sophos/servers.html"},
    ))
    [error] = result.errors
    assert error.category == IssueCategory.UI_CHANGED
    assert error.stage == "dispositivos/computador"
    assert "nome" in error.message and "'Hostname'" in error.message
    assert len(result.datasets["dispositivos"]) == 2
    assert len(result.datasets["alertas"]) == 3
    assert result.status == "parcial"


def test_page_without_table_is_ui_change(driver, site_url):
    result = collect(driver, site_url, pages(dispositivos={"computador": "/blank.html"}, alertas={}), timeout=1)
    [error] = result.errors
    assert error.category == IssueCategory.UI_CHANGED and "Tabela não encontrada" in error.message
    assert result.status == "falha"


def test_session_expired_stops_collection(driver, site_url):
    result = collect(driver, site_url, pages(
        dispositivos={"computador": "/sophos/expired.html", "servidor": "/sophos/servers.html"},
    ))
    first, interrupted = result.errors
    assert first.category == IssueCategory.AUTHENTICATION and "sessão expirou" in first.message
    assert "dispositivos/servidor" in interrupted.message and "alertas/alerta" in interrupted.message
    assert result.datasets == {"dispositivos": [], "alertas": []}


def test_endless_loading_is_timeout(driver, site_url):
    result = collect(driver, site_url, pages(dispositivos={"computador": "/sophos/loading.html"}, alertas={}), timeout=1)
    [error] = result.errors
    assert error.category == IssueCategory.TIMEOUT


def test_transient_failure_is_retried(driver, site_url):
    flaky = f"/sophos/flaky.html?k={uuid.uuid4().hex}"
    result = collect(driver, site_url, pages(dispositivos={"computador": flaky}, alertas={}), timeout=1, retries=1)
    assert result.errors == []
    assert [d["nome"] for d in result.datasets["dispositivos"]] == ["PC-RETRY"]


def test_empty_list_is_not_an_error(driver, site_url):
    result = collect(driver, site_url, pages(dispositivos={"computador": "/sophos/empty.html"}, alertas={}))
    assert result.status == "sucesso" and result.datasets["dispositivos"] == []


def test_unreachable_platform_is_unavailability(driver, site_url):
    result = collect(driver, site_url, pages(dispositivos={"computador": "http://127.0.0.1:1/x"}, alertas={}))
    [error] = result.errors
    assert error.category == IssueCategory.UNAVAILABLE


# --- fluxo completo: login + coleta ------------------------------------------------

LOGIN_SELECTORS = {"username": ["#name"], "submit": ["#enter"], "error": ["div.red"], "success": ["aside.sidebar"]}


def platform_for_run(site_url):
    return PlatformConfig(
        name="sophos", kind="sophos", url=f"{site_url}/login.html", enabled=True,
        selectors=LOGIN_SELECTORS, params={"timeout": 3, **DEFAULT_PAGES},
    )


def test_run_collection_logs_in_and_collects(site_url, driver_factory):
    CredentialStore().set("sophos", "operador", "S3nh@-forte")
    result = run_collection(platform_for_run(site_url), Settings(), CredentialStore(), driver_factory)
    assert result.status == "sucesso", result.issues
    assert result.counts() == {"dispositivos": 27, "alertas": 3}
    assert result.finished_at


def test_run_collection_records_authentication_failure(site_url, driver_factory):
    CredentialStore().set("sophos", "operador", "senha-errada")
    result = run_collection(platform_for_run(site_url), Settings(login_timeout=5), CredentialStore(), driver_factory)
    [error] = result.errors
    assert error.category == IssueCategory.AUTHENTICATION and "Usuário ou senha incorretos" in error.message
    assert result.status == "falha"

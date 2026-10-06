"""Feature 9.2: verificação de login, páginas e colunas (jervis check) com navegador real."""

import json

import pytest

from jervis.check import check_platform
from jervis.config import PlatformConfig, Settings
from jervis.credentials import CredentialStore

pytestmark = pytest.mark.browser

LOGIN = {"username": ["#name"], "submit": ["#enter"], "error": ["div.red"], "success": ["aside.sidebar"]}


def sophos(site_url, pages):
    return PlatformConfig(name="sophos", kind="sophos", url=f"{site_url}/login.html", enabled=True, selectors=LOGIN,
                          params={"timeout": 3, "dispositivos": {"pages": pages}, "alertas": {"pages": {}}})


def run_check(site_url, driver_factory, pages, password="S3nh@-forte", tmp_path=None):
    store = CredentialStore(environ={})
    store.set("sophos", "operador", password)
    lines = []
    report = check_platform(sophos(site_url, pages), Settings(login_timeout=5), store, driver_factory,
                            progress=lines.append, screenshot_dir=tmp_path)
    return report, lines


def test_check_reports_columns_found_and_missing(site_url, driver_factory, tmp_path):
    report, lines = run_check(site_url, driver_factory, {
        "computador": "/sophos/computers.html", "parcial": "/sophos/partial.html", "alterada": "/sophos/changed.html",
    }, tmp_path=tmp_path)
    assert report["login"]["resultado"] == "ok"
    pages = {p["etapa"]: p for p in report["paginas"]}

    ok = pages["dispositivos/computador"]
    assert ok["resultado"] == "ok" and ok["linhas_primeira_pagina"] == 10 and ok["paginacao"] is True
    assert ok["mapeamento"]["status_agente"] == "Integridade" and ok["exemplo"]["nome"] == "PC-001"

    partial = pages["dispositivos/parcial"]
    assert partial["resultado"] == "aviso"
    assert partial["esperadas_ausentes"] == ["status_agente", "ultima_comunicacao", "situacao_protecao"]

    changed = pages["dispositivos/alterada"]
    assert changed["resultado"] == "falha" and changed["obrigatorias_ausentes"] == ["nome"]
    assert changed["colunas_na_pagina"] == ["Hostname", "Platform"]  # o que existe na tela, para ajustar o rótulo

    assert report["resultado"] == "falha"
    assert any("dispositivos/alterada: FALHA" in line for line in lines)
    assert all(p["captura"] and (tmp_path / p["captura"].split("\\")[-1]).exists() for p in report["paginas"])


def test_check_page_without_table(site_url, driver_factory):
    report, _ = run_check(site_url, driver_factory, {"vazia": "/blank.html"})
    [page] = report["paginas"]
    assert page["resultado"] == "falha" and page["categoria"] == "interface_alterada"


def test_check_login_failure(site_url, driver_factory):
    report, lines = run_check(site_url, driver_factory, {"computador": "/sophos/computers.html"}, password="errada")
    assert report["login"]["resultado"] == "falha" and "Usuário ou senha incorretos" in report["login"]["mensagem"]
    assert report["paginas"] == [] and report["resultado"] == "falha"
    assert lines[0].startswith("login: FALHA")


def test_check_report_is_json_serializable(site_url, driver_factory):
    report, _ = run_check(site_url, driver_factory, {"computador": "/sophos/computers.html"})
    assert json.loads(json.dumps(report))["resultado"] == "ok"

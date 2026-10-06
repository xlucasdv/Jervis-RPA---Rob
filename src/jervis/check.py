"""Verificação dos fluxos de navegação contra as plataformas reais (Feature 9.2).

``jervis check`` faz login e visita cada página configurada, conferindo se a tabela e as
colunas esperadas são encontradas — sem coletar nem gravar dados. É o primeiro passo ao
apontar a ferramenta para um ambiente novo ou depois de uma atualização da plataforma:
o resultado mostra as colunas que existem na tela, para ajustar ``params.<conjunto>.columns``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from selenium.common.exceptions import WebDriverException

from jervis.browser import create_driver
from jervis.collectors import build_collector
from jervis.collectors.models import now_iso
from jervis.config import PlatformConfig, Settings
from jervis.credentials import CredentialStore
from jervis.errors import JervisError
from jervis.fileutil import atomic_write_text
from jervis.security import redact
from jervis.session import DriverFactory, platform_session


def check_platform(
    platform: PlatformConfig,
    settings: Settings,
    store: CredentialStore,
    driver_factory: DriverFactory = create_driver,
    progress: Callable[[str], None] = print,
    screenshot_dir: Path | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {"plataforma": platform.name, "tipo": platform.kind, "url": platform.url,
                              "verificado_em": now_iso(), "login": None, "paginas": []}
    started = time.monotonic()
    try:
        collector = build_collector(platform, settings)
        with platform_session(platform, settings, store, driver_factory) as (driver, login):
            report["login"] = {"resultado": "ok", "url_apos_login": login.url, "mfa": login.used_mfa,
                               "tempo_s": round(login.elapsed, 1)}
            progress(f"login: OK em {login.elapsed:.1f}s{' (com MFA)' if login.used_mfa else ''} — {login.url}")
            report["paginas"] = collector.inspect(driver, login.url, progress, screenshot_dir)
    except JervisError as exc:
        report["login"] = report["login"] or {"resultado": "falha", "mensagem": str(exc)}
        if report["login"]["resultado"] == "falha":
            progress(f"login: FALHA — {exc}")
        else:
            report["erro"] = str(exc)
    except WebDriverException as exc:
        report["erro"] = f"Erro do navegador: {(exc.msg or str(exc)).strip()}"
        progress(report["erro"])
    report["tempo_s"] = round(time.monotonic() - started, 1)
    report["resultado"] = overall(report)
    return report


def overall(report: dict[str, Any]) -> str:
    if (report.get("login") or {}).get("resultado") != "ok" or report.get("erro"):
        return "falha"
    results = {p["resultado"] for p in report["paginas"]}
    if "falha" in results:
        return "falha"
    return "aviso" if "aviso" in results else "ok"


def save_check(report: dict[str, Any], directory: Path) -> Path:
    stamp = report["verificado_em"][:19].replace(":", "").replace("-", "").replace("T", "-")
    path = directory / f"{report['plataforma']}-{stamp}.json"
    return atomic_write_text(path, redact(json.dumps(report, ensure_ascii=False, indent=2)))

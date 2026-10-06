"""Evidências para diagnóstico de falhas (capturas de tela)."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from selenium.webdriver.remote.webdriver import WebDriver

from jervis.config import Settings

log = logging.getLogger(__name__)


def save_screenshot(driver: WebDriver, settings: Settings, platform: str, stage: str = "") -> str | None:
    """Salva a tela atual se ``screenshot_on_failure`` estiver ativo. Nunca lança exceção."""
    if not settings.screenshot_on_failure:
        return None
    suffix = f"-{re.sub(r'[^A-Za-z0-9_-]+', '_', stage)}" if stage else ""
    path = Path(settings.screenshot_dir) / f"{platform}{suffix}-{time.strftime('%Y%m%d-%H%M%S')}.png"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        driver.save_screenshot(str(path))
    except Exception:  # a captura é diagnóstico; nunca deve mascarar o erro original
        log.warning("[%s] Não foi possível salvar a captura de tela da falha", platform, exc_info=True)
        return None
    log.info("[%s] Captura de tela da falha salva em %s", platform, path)
    return str(path)

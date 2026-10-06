"""Relatório em PDF: o HTML de impressão é impresso pelo próprio navegador da ferramenta.

Assim o PDF tem exatamente o visual do HTML, sem outra biblioteca de layout.
"""

from __future__ import annotations

import base64
from pathlib import Path

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.print_page_options import PrintOptions

from jervis.browser import create_driver
from jervis.config import Settings
from jervis.errors import BrowserError
from jervis.fileutil import atomic_write_text


def write_pdf(html: str, path: Path, settings: Settings) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    source = atomic_write_text(path.with_name(f".{path.stem}-impressao.html"), html)
    try:
        driver = create_driver(settings, headless=True)
        try:
            driver.get(source.resolve().as_uri())
            options = PrintOptions()
            options.orientation = "landscape"
            options.background = True  # mantém as cores das classificações
            options.margin_top = options.margin_bottom = options.margin_left = options.margin_right = 1.0
            pdf = base64.b64decode(driver.print_page(options))
        except WebDriverException as exc:
            raise BrowserError(f"O navegador não conseguiu gerar o PDF: {(exc.msg or str(exc)).strip()}") from exc
        finally:
            driver.quit()
    finally:
        source.unlink(missing_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(pdf)
    tmp.replace(path)
    return path

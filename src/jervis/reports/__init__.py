"""Geração de relatórios (Épico 6) a partir do consolidado: HTML, PDF, Excel e CSV."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jervis.config import REPORT_FORMATS, Settings

__all__ = ["REPORT_FORMATS", "ReportOutput", "generate_reports"]
from jervis.consolidation.consolidate import CONSOLIDATED_CSV, to_csv
from jervis.errors import JervisError
from jervis.fileutil import atomic_write_text
from jervis.reports.data import build_report_data
from jervis.reports.excel import write_excel
from jervis.reports.html import render_slides
from jervis.reports.pdf import SLIDE_PAGE_CM, write_pdf
from jervis.reports.slides import build_slides, logo_data_uri
from jervis.security import redact

log = logging.getLogger(__name__)

REPORT_BASENAME = "relatorio"


@dataclass
class ReportOutput:
    files: dict[str, list[Path]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def generate_reports(
    consolidated: dict[str, Any], run_dir: Path, formats: list[str] | tuple[str, ...], settings: Settings,
    meta: dict[str, Any] | None = None, basename: str = REPORT_BASENAME,
) -> ReportOutput:
    """Gera cada formato pedido; a falha de um formato (ex.: PDF sem navegador) não impede os demais.

    ``meta``: cliente, tipo e período do relatório e notas da equipe (ver reports.slides).
    """
    data = build_report_data(consolidated, settings.report_title)
    data["slides"] = build_slides(data, consolidated, meta, settings.report_company, logo_data_uri(settings.report_logo))
    output = ReportOutput()
    for fmt in formats:
        try:
            output.files[fmt] = _GENERATORS[fmt](data, consolidated, run_dir, settings, basename)
        except (JervisError, OSError) as exc:
            output.errors[fmt] = str(exc)
            log.error("Falha ao gerar o relatório %s: %s", fmt, exc)
    return output


def _html(data, consolidated, run_dir: Path, settings, basename: str) -> list[Path]:
    return [atomic_write_text(run_dir / f"{basename}.html", redact(render_slides(data["slides"])))]


def _pdf(data, consolidated, run_dir: Path, settings, basename: str) -> list[Path]:
    return [write_pdf(redact(render_slides(data["slides"])), run_dir / f"{basename}.pdf", settings, SLIDE_PAGE_CM)]


def _xlsx(data, consolidated, run_dir: Path, settings, basename: str) -> list[Path]:
    return [write_excel(data, run_dir / f"{basename}.xlsx")]


def _csv(data, consolidated, run_dir: Path, settings, basename: str) -> list[Path]:
    """CSV consolidado (todas as plataformas) e um por plataforma."""
    records = consolidated["registros"]
    paths = [atomic_write_text(run_dir / CONSOLIDATED_CSV, redact(to_csv(records)), encoding="utf-8-sig")]
    for source in consolidated["fontes"]:
        name = source["plataforma"]
        subset = [r for r in records if r["plataforma"] == name]
        paths.append(atomic_write_text(run_dir / f"{REPORT_BASENAME}_{name}.csv", redact(to_csv(subset)), encoding="utf-8-sig"))
    return paths


_GENERATORS = {"html": _html, "xlsx": _xlsx, "csv": _csv, "pdf": _pdf}

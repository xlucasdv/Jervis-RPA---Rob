"""Relatório em HTML no padrão de apresentação (arquivo único, sem dependências externas; também é a base do PDF)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape


def format_datetime(value: str | None) -> str:
    """ISO → '06/10/2026 09:41' (horário local da coleta)."""
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return str(value)


_env = Environment(
    loader=PackageLoader("jervis.reports", "templates"),
    # Os dados vêm de telas de terceiros: todo texto é escapado.
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["dt"] = format_datetime
_env.filters["num"] = lambda v: (f"{v:,}".replace(",", ".") if isinstance(v, int) else f"{v:.2f}".replace(".", ",")
                                 if isinstance(v, float) else v)


def render_executive(document: dict[str, Any]) -> str:
    """Relatório executivo (documento A4)."""
    return _env.get_template("executivo.html.j2").render(e=document)


def render_slides(slides: dict[str, Any]) -> str:
    """Relatório no padrão de apresentação (páginas 16:9); base do HTML e do PDF."""
    return _env.get_template("slides.html.j2").render(s=slides)


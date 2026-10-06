"""Limpeza e validação dos dados (Feature 5.2)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from jervis.consolidation.model import CLASSIFICATIONS, PRIORITY, REQUIRED_FIELDS, SEVERITIES, StandardRecord

# Textos que as telas usam para "sem valor".
_PLACEHOLDERS = frozenset({"", "-", "--", "—", "–", "n/a", "na", "n/d", "nd", "null", "none", "undefined", "?"})


def clean_value(value: Any) -> Any:
    """Espaços extras removidos; marcadores de "vazio" ('—', 'N/A'...) viram None."""
    if isinstance(value, str):
        text = " ".join(value.split())
        return None if text.lower() in _PLACEHOLDERS else text
    return value


def clean_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: clean_value(value) for key, value in row.items()}


def validate(record: StandardRecord) -> str | None:
    """Motivo do descarte, ou None se o registro é válido."""
    missing = [name for name in REQUIRED_FIELDS if not getattr(record, name)]
    if missing:
        return f"campo(s) obrigatório(s) ausente(s): {', '.join(missing)}"
    if record.classificacao not in CLASSIFICATIONS:
        return f"classificação inválida: {record.classificacao}"
    return None


def check_consistency(record: StandardRecord, collected_at: datetime | None) -> None:
    """Anota (sem descartar) valores inconsistentes em ``observacoes``."""
    if record.severidade is not None and record.severidade not in SEVERITIES:
        record.observacoes.append(f"Severidade fora da escala padrão: '{record.severidade}'.")
        record.severidade = None
    if record.data_evento and collected_at:
        try:
            event = datetime.fromisoformat(record.data_evento)
        except ValueError:
            record.observacoes.append(f"Data do evento inválida: '{record.data_evento}'.")
            record.data_evento = None
            return
        if event.tzinfo and collected_at.tzinfo is None:
            collected_at = collected_at.astimezone()
        if event.tzinfo is None and collected_at.tzinfo:
            event = event.astimezone()
        if event > collected_at + timedelta(days=1):
            record.observacoes.append("Data do evento posterior à data da coleta (relógio ou fuso inconsistente).")


def deduplicate(records: list[StandardRecord]) -> tuple[list[StandardRecord], int]:
    """Remove registros repetidos (mesma plataforma, categoria e chave), mantendo o mais urgente.

    Ex.: um problema do Zabbix que aparece nas origens "ativo" e "historico_24h";
    um dispositivo listado em duas páginas da Sophos.
    """
    kept: dict[str, StandardRecord] = {}
    origins: dict[str, list[str]] = {}
    for record in records:
        rid = record.id
        if rid not in kept:
            kept[rid] = record
            origins[rid] = [record.origem] if record.origem else []
            continue
        if record.origem and record.origem not in origins[rid]:
            origins[rid].append(record.origem)
        if PRIORITY[record.classificacao] < PRIORITY[kept[rid].classificacao]:
            kept[rid] = record
    for rid, record in kept.items():
        others = [o for o in origins[rid] if o != record.origem]
        if others:
            record.observacoes.append(f"Também encontrado em: {', '.join(others)}.")
    return list(kept.values()), len(records) - len(kept)

"""Consolidação das informações (Feature 5.4): Sophos, Acronis e Zabbix em uma estrutura única.

Entrada: os resultados de coleta (``<plataforma>.json`` de uma execução).
Saída: ``consolidado.json`` (estrutura completa para o relatório) e ``consolidado.csv``
(planilha com um registro por linha, pronta para o Excel).
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from jervis.collectors.models import now_iso
from jervis.consolidation.cleaning import check_consistency, clean_row, deduplicate, validate
from jervis.consolidation.model import CLASSIFICATIONS, SEVERITIES, StandardRecord
from jervis.consolidation.rules import AUXILIARY_DATASETS, MAPPERS, Context, Options, collection_issue
from jervis.errors import ConfigError
from jervis.fileutil import atomic_write_text
from jervis.security import redact

log = logging.getLogger(__name__)

CONSOLIDATED_JSON = "consolidado.json"
CONSOLIDATED_CSV = "consolidado.csv"

CSV_COLUMNS = (
    "prioridade", "classificacao", "plataforma", "ambiente", "categoria", "recurso", "status",
    "severidade", "mensagem", "data_evento", "data_coleta", "observacoes", "origem", "id",
)

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def consolidate(results: list[dict[str, Any]], options: Options | None = None) -> dict[str, Any]:
    options = options or Options()
    records: list[StandardRecord] = []
    discarded: list[dict[str, Any]] = []
    ignored: set[str] = set()
    sources = []
    received = 0

    for result in results:
        kind, platform = result.get("kind"), result.get("platform")
        collected_text = result.get("finished_at") or result.get("started_at")
        base = dict(
            plataforma=platform, tipo_plataforma=kind, ambiente=result.get("environment") or "",
            data_coleta=collected_text, collected_at=_parse_iso(collected_text), options=options,
        )
        sources.append({
            "plataforma": platform,
            "tipo": kind,
            "ambiente": result.get("environment") or "",
            "status_coleta": result.get("status"),
            "data_coleta": collected_text,
            "registros_coletados": result.get("counts", {}),
            "falhas_coleta": sum(1 for i in result.get("issues", []) if i.get("severity") == "erro"),
        })

        for dataset, rows in (result.get("datasets") or {}).items():
            mapper = MAPPERS.get((kind, dataset))
            if mapper is None:
                if (kind, dataset) not in AUXILIARY_DATASETS:
                    ignored.add(f"{platform}/{dataset}")
                continue
            for row in rows:
                received += 1
                ctx = Context(origem=f"{dataset}/{row.get('origem') or dataset}", **base)
                _accept(mapper(clean_row(row), ctx), row, records, discarded)

        for issue in result.get("issues", []):
            received += 1
            ctx = Context(origem="coleta", **base)
            _accept(collection_issue(issue, ctx), issue, records, discarded)

    for rec in records:
        check_consistency(rec, _parse_iso(rec.data_coleta))
    records, duplicates = deduplicate(records)
    records.sort(key=_sort_key)

    return {
        "gerado_em": now_iso(),
        "fontes": sources,
        "resumo": _summary(records),
        "validacao": {
            "registros_recebidos": received,
            "registros_consolidados": len(records),
            "duplicados_removidos": duplicates,
            "descartados": discarded,
            "com_observacoes": sum(1 for r in records if r.observacoes),
            "conjuntos_ignorados": sorted(ignored),
        },
        "registros": [r.to_dict() for r in records],
    }


def _accept(rec: StandardRecord, original: dict[str, Any], records: list, discarded: list) -> None:
    rec.detalhes = original
    reason = validate(rec)
    if reason:
        discarded.append({"plataforma": rec.plataforma, "categoria": rec.categoria, "origem": rec.origem, "motivo": reason})
        log.warning("[%s] Registro descartado (%s): %s", rec.plataforma, rec.origem, reason)
    else:
        records.append(rec)


def _sort_key(rec: StandardRecord) -> tuple:
    return (
        rec.prioridade,
        CLASSIFICATIONS.index(rec.classificacao),
        _SEVERITY_RANK.get(rec.severidade, len(SEVERITIES)),
        rec.plataforma,
        rec.categoria,
        (rec.recurso or "").lower(),
    )


def _summary(records: list[StandardRecord]) -> dict[str, Any]:
    def by_classification(items) -> dict[str, int]:
        counts = Counter(r.classificacao for r in items)
        return {c: counts[c] for c in CLASSIFICATIONS if counts[c]}

    grouped_platform: dict[str, list] = defaultdict(list)
    grouped_category: dict[str, list] = defaultdict(list)
    for rec in records:
        grouped_platform[rec.plataforma].append(rec)
        grouped_category[rec.categoria].append(rec)
    return {
        "total": len(records),
        "por_classificacao": by_classification(records),
        "por_plataforma": {name: by_classification(items) for name, items in grouped_platform.items()},
        "por_categoria": {name: by_classification(items) for name, items in grouped_category.items()},
    }


def _parse_iso(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


# --- arquivos -------------------------------------------------------------------------


def load_run(run_dir: Path) -> list[dict[str, Any]]:
    """Lê os resultados de coleta de uma execução (ignora o próprio consolidado)."""
    if not run_dir.is_dir():
        raise ConfigError(f"Diretório de execução não encontrado: {run_dir}")
    results = []
    for path in sorted(run_dir.glob("*.json")):
        if path.name in (CONSOLIDATED_JSON, "execucao.json") or path.name.startswith("."):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Arquivo de resultado ilegível ignorado: %s (%s)", path, exc)
            continue
        if isinstance(data, dict) and {"platform", "kind", "datasets"} <= set(data):
            results.append(data)
        else:
            log.warning("Arquivo ignorado (não é um resultado de coleta): %s", path)
    if not results:
        raise ConfigError(f"Nenhum resultado de coleta encontrado em {run_dir}.")
    return results


def latest_run_dir(base: str | Path) -> Path:
    runs = sorted(
        (d for d in Path(base).iterdir() if d.is_dir() and any(d.glob("*.json"))),
        key=lambda d: d.name,
    ) if Path(base).is_dir() else []
    if not runs:
        raise ConfigError(f"Nenhuma execução de coleta encontrada em {base}. Execute 'jervis collect' primeiro.")
    return runs[-1]


def write_outputs(report: dict[str, Any], run_dir: Path) -> tuple[Path, Path]:
    json_path = atomic_write_text(run_dir / CONSOLIDATED_JSON, redact(json.dumps(report, ensure_ascii=False, indent=2)))
    csv_path = atomic_write_text(run_dir / CONSOLIDATED_CSV, redact(to_csv(report["registros"])), encoding="utf-8-sig")
    return json_path, csv_path


def to_csv(records: list[dict[str, Any]]) -> str:
    """CSV com ';' e BOM UTF-8: abre corretamente no Excel em português."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for rec in records:
        writer.writerow(
            " | ".join(rec["observacoes"]) if col == "observacoes" else ("" if rec.get(col) is None else rec[col])
            for col in CSV_COLUMNS
        )
    return buffer.getvalue()

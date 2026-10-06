"""Relatório em Excel (.xlsx): resumo, consolidado, uma aba por plataforma e qualidade dos dados."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from jervis.reports.data import CLASSIFICATION_STYLE

BRAND = "1F4E79"
HEADER_FILL = PatternFill("solid", fgColor="EEF2F6")
THIN = Side(style="thin", color="DDE3E9")

# (título, chave, largura)
RECORD_COLUMNS = (
    ("Prioridade", "prioridade", 10),
    ("Classificação", "classificacao", 16),
    ("Plataforma", "plataforma", 12),
    ("Ambiente", "ambiente", 12),
    ("Categoria", "categoria", 26),
    ("Recurso", "recurso", 24),
    ("Situação / mensagem", "mensagem", 60),
    ("Status na plataforma", "status", 30),
    ("Severidade", "severidade", 11),
    ("Data do evento", "data_evento", 17),
    ("Data da coleta", "data_coleta", 17),
    ("Observações", "observacoes", 50),
    ("Origem", "origem", 24),
    ("ID", "id", 18),
)


def write_excel(data: dict[str, Any], path: Path) -> Path:
    wb = Workbook()
    _summary_sheet(wb.active, data)
    all_records = [r for p in data["plataformas"] for cat in p["categorias"] for r in cat["registros"]]
    all_records.sort(key=lambda r: r["prioridade"])
    _records_sheet(wb.create_sheet("Consolidado"), all_records, data)
    for p in data["plataformas"]:
        records = [r for cat in p["categorias"] for r in cat["registros"]]
        _records_sheet(wb.create_sheet(_sheet_name(p["nome"], wb)), records, data)
    _quality_sheet(wb.create_sheet("Qualidade dos dados"), data)
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return path


def _summary_sheet(ws: Worksheet, data: dict[str, Any]) -> None:
    ws.title = "Resumo"
    ws["A1"] = data["titulo"]
    ws["A1"].font = Font(size=16, bold=True, color=BRAND)
    ws["A2"] = f"Gerado em {_to_datetime(data['gerado_em']):%d/%m/%Y %H:%M}" if data.get("gerado_em") else ""
    ws["A2"].font = Font(color="5F6B78")

    e = data["executivo"]
    no_backups, no_hosts = not e["cobertura"]["backups"]["com_dados"], not e["cobertura"]["hosts"]["com_dados"]
    indicators = [
        ("Total de dispositivos", e["dispositivos"]["total"], None),
        ("Total de alertas", e["alertas"]["total"], "atencao" if e["alertas"]["ativos"] else None),
        ("Alertas ativos", e["alertas"]["ativos"], "atencao" if e["alertas"]["ativos"] else None),
        ("Problemas críticos", e["criticos"], "critico" if e["criticos"] else "normal"),
        ("Backups com falha", "sem dados" if no_backups else e["backups_com_falha"],
         "falha_coleta" if no_backups else ("critico" if e["backups_com_falha"] else "normal")),
        ("Backups em atenção", "sem dados" if no_backups else e["backups_em_atencao"],
         "falha_coleta" if no_backups else ("atencao" if e["backups_em_atencao"] else None)),
        ("Hosts indisponíveis", "sem dados" if no_hosts else e["hosts_indisponiveis"],
         "falha_coleta" if no_hosts else ("indisponivel" if e["hosts_indisponiveis"] else "normal")),
        ("Plataformas sem resposta", len(e["plataformas_sem_resposta"]), "falha_coleta" if e["plataformas_sem_resposta"] else "normal"),
    ]
    row = 4
    _header(ws, row, ["Resumo executivo", "Valor"])
    for label, value, tone in indicators:
        row += 1
        ws.cell(row, 1, label)
        cell = ws.cell(row, 2, value)
        cell.font = Font(bold=True)
        if tone:
            _paint(cell, tone)
    if e["plataformas_sem_resposta"]:
        row += 1
        ws.cell(row, 1, "Sem resposta: " + ", ".join(e["plataformas_sem_resposta"])).font = Font(italic=True, color="5F6B78")

    classes = data["classificacoes"]
    row += 2
    _header(ws, row, ["Plataforma", "Tipo", "Coleta", "Data da coleta", *[CLASSIFICATION_STYLE[c]["label"] for c in classes], "Total"])
    for p in data["plataformas"]:
        row += 1
        values = [p["nome"], p["titulo"], p["status_label"], _to_datetime(p["data_coleta"])]
        values += [p["por_classificacao"].get(c, 0) for c in classes] + [p["total"]]
        for col, value in enumerate(values, 1):
            cell = ws.cell(row, col, value)
            if isinstance(value, datetime):
                cell.number_format = "dd/mm/yyyy hh:mm"
        status_tone = {"sucesso": "normal", "parcial": "atencao", "falha": "falha_coleta"}.get(p["status_coleta"])
        if status_tone:
            _paint(ws.cell(row, 3), status_tone)
        for i, c in enumerate(classes):
            if p["por_classificacao"].get(c):
                _paint(ws.cell(row, 5 + i), c)

    row += 2
    _header(ws, row, ["Categoria", *[CLASSIFICATION_STYLE[c]["label"] for c in classes], "Total"])
    for cat, by_class in data["resumo"]["por_categoria"].items():
        row += 1
        ws.cell(row, 1, data["categorias"].get(cat, cat))
        for i, c in enumerate(classes):
            ws.cell(row, 2 + i, by_class.get(c, 0))
        ws.cell(row, 2 + len(classes), sum(by_class.values())).font = Font(bold=True)

    for col, width in enumerate((34, 24, 16, 17, 12, 13, 15, 12, 12, 10), 1):
        ws.column_dimensions[get_column_letter(col)].width = width


def _records_sheet(ws: Worksheet, records: list[dict[str, Any]], data: dict[str, Any]) -> None:
    _header(ws, 1, [title for title, _, _ in RECORD_COLUMNS])
    for row, record in enumerate(records, 2):
        for col, (_, key, _) in enumerate(RECORD_COLUMNS, 1):
            value = record.get(key)
            if key == "classificacao":
                value = CLASSIFICATION_STYLE[value]["label"]
            elif key == "categoria":
                value = data["categorias"].get(value, value)
            elif key == "observacoes":
                value = " | ".join(value) if value else None
            elif key in ("data_evento", "data_coleta"):
                value = _to_datetime(value)
            cell = ws.cell(row, col, value)
            if isinstance(value, datetime):
                cell.number_format = "dd/mm/yyyy hh:mm"
            if key in ("mensagem", "observacoes", "status"):
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        _paint(ws.cell(row, 2), record["classificacao"])
        _paint(ws.cell(row, 1), record["classificacao"])
    for col, (_, _, width) in enumerate(RECORD_COLUMNS, 1):
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.freeze_panes = "C2"
    if records:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(RECORD_COLUMNS))}{len(records) + 1}"


def _quality_sheet(ws: Worksheet, data: dict[str, Any]) -> None:
    v = data["validacao"]
    _header(ws, 1, ["Indicador", "Valor"])
    rows = [
        ("Registros recebidos das coletas", v["registros_recebidos"]),
        ("Registros consolidados", v["registros_consolidados"]),
        ("Duplicidades removidas", v["duplicados_removidos"]),
        ("Descartados por dados obrigatórios ausentes", len(v["descartados"])),
        ("Registros com observações", v["com_observacoes"]),
        ("Conjuntos sem regra de consolidação", ", ".join(v["conjuntos_ignorados"]) or "—"),
    ]
    for i, (label, value) in enumerate(rows, 2):
        ws.cell(i, 1, label)
        ws.cell(i, 2, value)
    if v["descartados"]:
        start = len(rows) + 3
        _header(ws, start, ["Plataforma", "Categoria", "Origem", "Motivo"])
        for i, x in enumerate(v["descartados"], start + 1):
            for col, key in enumerate(("plataforma", "categoria", "origem", "motivo"), 1):
                ws.cell(i, col, x.get(key))
    for col, width in enumerate((44, 30, 26, 60), 1):
        ws.column_dimensions[get_column_letter(col)].width = width


def _header(ws: Worksheet, row: int, titles: list[str]) -> None:
    for col, title in enumerate(titles, 1):
        cell = ws.cell(row, col, title)
        cell.font = Font(bold=True, color=BRAND)
        cell.fill = HEADER_FILL
        cell.border = Border(bottom=THIN)


def _paint(cell, classification: str) -> None:
    style = CLASSIFICATION_STYLE[classification]
    cell.fill = PatternFill("solid", fgColor=style["fill"])
    cell.font = Font(bold=True, color=style["font"])


def _to_datetime(value: str | None) -> datetime | None:
    """Excel não guarda fuso: converte para o horário local, sem fuso."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone().replace(tzinfo=None) if parsed.tzinfo else parsed


def _sheet_name(name: str, wb: Workbook) -> str:
    base = re.sub(r"[\[\]:*?/\\]", "_", name)[:31] or "Plataforma"
    candidate, n = base, 2
    while candidate in wb.sheetnames:
        candidate = f"{base[:28]}_{n}"
        n += 1
    return candidate

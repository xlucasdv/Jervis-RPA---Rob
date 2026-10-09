"""Relatório no padrão de apresentação da Contego (páginas 16:9): capa, destaques, uma página por serviço com
indicadores, gráfico e observações, recomendações priorizadas e anexo com os itens prioritários.

Os textos de observações e recomendações são derivados dos dados; destaques, notas e recomendações escritos
pela equipe vêm de um arquivo de notas opcional (ver ``load_notes``).
"""

from __future__ import annotations

import base64
import html
import math
import mimetypes
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from jervis.consolidation.model import (
    ATTENTION,
    CRITICAL,
    ENDPOINT,
    HOST,
    MONITORING_PROBLEM,
    NORMAL,
    SECURITY_ALERT,
    UNAVAILABLE,
)

# Paleta do modelo (fundo roxo escuro, destaques em roxo, amarelo, verde e azul).
GREEN, YELLOW, RED, BLUE, PURPLE, GREY = "#2fd6a0", "#f5b942", "#f0616d", "#4f8ff7", "#a67cf0", "#8f86a8"
TONE = {CRITICAL: RED, UNAVAILABLE: PURPLE, ATTENTION: YELLOW, NORMAL: GREEN}
CRITICALITY = {"alta": RED, "media": YELLOW, "baixa": GREEN, "decisao": BLUE}
CRITICALITY_LABEL = {"alta": "Alta", "media": "Média", "baixa": "Baixa", "decisao": "Decisão técnica"}
SEVERITY_LABEL = {"critica": "Crítica", "alta": "Alta", "media": "Média", "baixa": "Baixa", "informativa": "Informativa"}
ROWS_PER_APPENDIX_PAGE = 11
APPENDIX_PAGES = 4

SERVICE_INFO = {
    "acronis": ("shield", "Acronis Cyber Protect", "Proteção de endpoints e backup"),
    "zabbix": ("activity", "NOCaaS Monitor", "Monitoramento 24x7 (Zabbix)"),
    "sophos": ("server", "Sophos Central", "Proteção de endpoints"),
}

# Ícones no estilo de traço fino do modelo (caminhos SVG 24x24).
ICONS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "server": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/>'
              '<line x1="7" y1="6.5" x2="7.01" y2="6.5"/><line x1="7" y1="17.5" x2="7.01" y2="17.5"/>',
    "monitor": '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/>'
               '<line x1="12" y1="17" x2="12" y2="21"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'
             '<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "database": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/>'
                '<path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    "check": '<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><polyline points="22 4 12 14 9 11"/>',
    "info": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    "wifi": '<path d="M5 12.6a10 10 0 0 1 14 0"/><path d="M8.5 16.1a5 5 0 0 1 7 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    "tool": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-.5-.5-2.5z"/>',
    "list": '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/>'
            '<line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
}


def icon(name: str, size: int = 22) -> str:
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round">{ICONS.get(name, ICONS["info"])}</svg>')


# --- gráficos (SVG desenhado no servidor: funciona no PDF, sem internet) -----------------


def donut(segments: list[tuple[str, int, str]], size: int = 230, thickness: int = 46) -> str:
    """Rosca com o valor de cada fatia escrito sobre ela (como no modelo)."""
    total = sum(v for _, v, _ in segments)
    if not total:
        return '<div class="empty">Sem dados no período</div>'
    r, c = (size - thickness) / 2, size / 2
    circumference = 2 * math.pi * r
    parts, offset, labels = [], 0.0, []
    for _, value, color in segments:
        if not value:
            continue
        length = circumference * value / total
        parts.append(f'<circle cx="{c}" cy="{c}" r="{r}" fill="none" stroke="{color}" stroke-width="{thickness}" '
                     f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" stroke-dashoffset="{-offset:.2f}" '
                     f'transform="rotate(-90 {c} {c})"/>')
        middle = (offset + length / 2) / circumference * 2 * math.pi - math.pi / 2
        if value / total >= 0.04:
            labels.append(f'<text x="{c + r * math.cos(middle):.1f}" y="{c + r * math.sin(middle):.1f}" '
                          f'dominant-baseline="central" text-anchor="middle">{value}</text>')
        offset += length
    return (f'<svg class="donut" width="{size}" height="{size}" viewBox="0 0 {size} {size}">{"".join(parts)}'
            f'<g class="donut-labels">{"".join(labels)}</g></svg>')


def legend(segments: list[tuple[str, int, str]]) -> str:
    return "".join(f'<span><i style="background:{color}"></i>{html.escape(label)}</span>'
                   for label, value, color in segments if value)


def bars(items: list[tuple[str, float, str]], color: str, max_value: float | None = None) -> str:
    """Barras horizontais com rótulo à esquerda e valor à direita."""
    if not items:
        return '<div class="empty">Sem dados no período</div>'
    top = max_value or max(v for _, v, _ in items) or 1
    rows = "".join(
        f'<div class="bar-row"><div class="bar-label" title="{html.escape(label)}">{html.escape(label)}</div>'
        f'<div class="bar-track"><div class="bar" style="width:{max(2, 100 * value / top):.1f}%;background:{color}"></div>'
        f'<span class="bar-value">{html.escape(shown)}</span></div></div>'
        for label, value, shown in items)
    return f'<div class="bars">{rows}</div>'


# --- notas escritas pela equipe ---------------------------------------------------------


def load_notes(path: Path | None) -> dict[str, Any]:
    """Arquivo YAML opcional com o que não vem das plataformas:

    destaques: [{titulo, texto, icone}]            → página "Destaques do mês"
    notas: [{titulo, selo, texto, proxima_acao}]   → página "Notas técnicas"
    melhorias: [{titulo, texto, icone}]            → página "Melhorias em andamento"
    recomendacoes: [{criticidade: alta|media|baixa|decisao, ponto, acao}]  → somadas às automáticas
    observacoes: {acronis: [texto], zabbix: [texto]}                      → somadas às automáticas
    """
    if not path or not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


# --- helpers de dados --------------------------------------------------------------------


def _by_origin(records: list[dict[str, Any]], platform: str, origin: str) -> list[dict[str, Any]]:
    return [r for r in records if r["plataforma"] == platform and (r.get("origem") or "").startswith(origin)]


def _pct(value: float) -> str:
    return f"{value:.2f}".replace(".", ",") + "%"


def _fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def _date(iso: str | None) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m/%Y") if iso else "—"
    except ValueError:
        return iso or "—"


def _names(rows: list[dict[str, Any]], limit: int = 6) -> str:
    names = [r["recurso"] for r in rows if r.get("recurso")]
    text = ", ".join(names[:limit])
    return text + (f" e mais {len(names) - limit}" if len(names) > limit else "")


def _kpi(label: str, value: str, note: str, color: str | None = None, icon_name: str = "info") -> dict[str, Any]:
    return {"label": label, "value": value, "note": note, "color": color, "icon": icon(icon_name)}


# --- páginas por serviço -----------------------------------------------------------------


def acronis_pages(platform: str, records: list[dict[str, Any]], summary: dict[str, Any]) -> tuple[list, list, list]:
    """(páginas, observações, recomendações) do Acronis por API."""
    machines = _by_origin(records, platform, "maquinas")
    alerts = _by_origin(records, platform, "alertas")
    activities = _by_origin(records, platform, "atividades")
    if not (machines or alerts or activities):
        return [], [], []
    details = [m.get("detalhes") or {} for m in machines]
    offline = [m for m in machines if (m.get("detalhes") or {}).get("online") is False]
    no_plan = [m for m in machines if "Sem plano de backup." in m.get("observacoes", [])]
    stale = [m for m in machines if "Backup desatualizado." in m.get("observacoes", [])]
    no_backup_ok = len(no_plan) + len(stale)
    crit_alerts = [a for a in alerts if (a.get("detalhes") or {}).get("severidade") == "critical"]
    mitigated = [a for a in alerts if (a.get("detalhes") or {}).get("mitigado")]
    act_errors = [a for a in activities if (a.get("detalhes") or {}).get("resultado") in ("error", "timedout", "abandoned")]

    kpis = [
        _kpi("Máquinas monitoradas", str(len(machines)), f"{len(machines) - len(offline)} online · {len(offline)} offline",
             None, "monitor"),
        _kpi("Sem backup em dia", str(no_backup_ok), f"{len(no_plan)} sem plano · {len(stale)} com backup desatualizado",
             RED if no_backup_ok else GREEN, "database"),
        _kpi("Alertas no período", _fmt_int(len(alerts)), f"{len(crit_alerts)} críticos · {len(mitigated)} ameaças mitigadas",
             YELLOW if alerts else GREEN, "alert"),
        _kpi("Atividades com erro", f"{len(act_errors)} / {len(activities)}", "tarefas executadas nas máquinas no período",
             YELLOW if act_errors else GREEN, "tool"),
    ]
    by_class = Counter(m["classificacao"] for m in machines)
    status_segments = [("Sem pendências", by_class[NORMAL], GREEN), ("Atenção", by_class[ATTENTION], YELLOW),
                       ("Crítico", by_class[CRITICAL], RED), ("Indisponível (offline)", by_class[UNAVAILABLE], PURPLE)]

    observations, recommendations = [], []
    if no_plan and len(no_plan) == len(machines):
        observations.append(("red", f"Nenhuma das {len(machines)} máquinas tem plano de backup aplicado no Acronis."))
        recommendations.append(("alta", f"Nenhuma das {len(machines)} máquinas tem plano de backup.",
                                "Confirmar com o cliente se o backup faz parte do escopo; se sim, aplicar plano de backup e validar a primeira execução."))
    elif no_plan:
        observations.append(("red", f"{len(no_plan)} máquina(s) sem plano de backup: {_names(no_plan)}."))
        recommendations.append(("alta", f"{len(no_plan)} máquina(s) sem plano de backup.", "Aplicar plano de backup e validar a execução."))
    if stale:
        oldest = min((d.get("ultimo_backup_iso") for d in (m.get("detalhes") or {} for m in stale) if d.get("ultimo_backup_iso")), default=None)
        observations.append(("red", f"{len(stale)} máquina(s) com backup desatualizado ou nunca concluído"
                                    + (f" (último backup mais antigo: {_date(oldest)})" if oldest else "") + "."))
        recommendations.append(("alta", f"{len(stale)} máquina(s) com backup desatualizado.",
                                "Verificar por que os backups pararam (agente, destino, credenciais) e executar um backup completo."))
    offline_alerts = [a for a in alerts if (a.get("detalhes") or {}).get("tipo") in ("MachineOffline30", "MachineOffline20")]
    if offline:
        longest = sorted(offline_alerts, key=lambda a: -int(re.search(r"(\d+) dias", a.get("mensagem") or "0 dias").group(1)))
        detail = f" Mais antiga: {longest[0]['recurso']} ({re.search(r'há (\d+) dias', longest[0]['mensagem']).group(1)} dias)." \
            if longest and re.search(r"há (\d+) dias", longest[0].get("mensagem") or "") else ""
        observations.append(("yellow", f"{len(offline)} máquina(s) offline.{detail}"))
        if offline_alerts:
            recommendations.append(("alta", f"{len(offline_alerts)} máquina(s) offline há mais de 20/30 dias.",
                                    "Confirmar se ainda estão em uso: reconectar o agente ou remover do console e liberar a licença."))
    incidents = [a for a in alerts if (a.get("detalhes") or {}).get("tipo") == "EDRIncidentDetected"]
    blocked = [a for a in alerts if (a.get("detalhes") or {}).get("tipo") in ("MaliciousUrlBlocked", "TotalProtectDeniedCategoryURLDetected")]
    if incidents or blocked:
        observations.append(("blue", f"Segurança: {len(incidents)} incidente(s) detectado(s) ({sum(1 for a in incidents if (a.get('detalhes') or {}).get('mitigado'))} mitigado(s)) "
                                     f"e {len(blocked)} URL(s) bloqueada(s)."))
        top = Counter(a["recurso"] for a in blocked + incidents).most_common(3)
        recommendations.append(("media", f"{len(incidents)} incidente(s) e {len(blocked)} URL(s) bloqueada(s) no período.",
                                "Revisar os incidentes no console e orientar os usuários das máquinas mais afetadas"
                                + (f" ({', '.join(f'{n} ({c})' for n, c in top)})" if top else "") + "."))
    patch = [a for a in alerts if (a.get("detalhes") or {}).get("tipo") == "PMInstallationFailed"]
    if patch:
        recommendations.append(("media", f"{len(patch)} falha(s) na instalação de patches.",
                                "Investigar as falhas (espaço em disco, reinicialização pendente) e reaplicar os patches."))
    disk = [a for a in alerts if (a.get("detalhes") or {}).get("tipo") == "MiMonitoringLowDiskSpace"]
    if disk:
        recommendations.append(("media", f"{len({a['recurso'] for a in disk})} máquina(s) com pouco espaço em disco.",
                                "Liberar espaço ou ampliar o disco antes que afete atualizações e backups."))
    if act_errors:
        top_errors = Counter((a.get("detalhes") or {}).get("titulo") for a in act_errors).most_common(2)
        observations.append(("yellow", f"{len(act_errors)} atividade(s) com erro no período; mais comuns: "
                                       + ", ".join(f"{t} ({n})" for t, n in top_errors) + "."))
    names = Counter((d.get("nome") or "").lower() for d in details if d.get("nome"))
    duplicated = [n for n, c in names.items() if c > 1]
    if duplicated:
        recommendations.append(("baixa", f"Máquina(s) registrada(s) em duplicidade no console: {', '.join(duplicated)}.",
                                "Remover os registros antigos para não distorcer contagens e licenças."))
    if not observations:
        observations.append(("green", "Sem pendências relevantes identificadas no período."))

    alert_types = Counter((a.get("detalhes") or {}).get("titulo") or a.get("mensagem") for a in alerts).most_common(7)
    act_by = Counter((a.get("detalhes") or {}).get("resultado_label") or a.get("status") for a in activities)
    act_segments = [("Concluído", act_by.get("Concluído", 0), GREEN), ("Erro", act_by.get("Erro", 0), RED),
                    ("Cancelado", act_by.get("Cancelado", 0), GREY),
                    ("Outros", sum(v for k, v in act_by.items() if k not in ("Concluído", "Erro", "Cancelado")), YELLOW)]
    pages = [
        {"kind": "service", "section": "Acronis", "title": "Acronis Cyber Protect – Visão Geral",
         "service": "Proteção de endpoints e backup", "kpis": kpis,
         "chart_title": f"Situação das Máquinas ({len(machines)} no total)", "chart": donut(status_segments),
         "legend": legend(status_segments), "panel_title": "Observações do Período", "panel_icon": icon("info"),
         "bullets": observations},
        {"kind": "two_charts", "section": "Acronis", "title": "Acronis – Alertas e Atividades",
         "service": "Alertas e tarefas do período",
         "left_title": f"Alertas por Tipo ({len(alerts)} no total)", "left": bars([(t, n, str(n)) for t, n in alert_types], BLUE),
         "right_title": f"Atividades por Resultado ({len(activities)} no total)", "right": donut(act_segments, 200, 40),
         "right_legend": legend(act_segments)},
    ]
    return pages, observations, recommendations


def zabbix_pages(platform: str, records: list[dict[str, Any]], summary: dict[str, Any]) -> tuple[list, list, list]:
    hosts = _by_origin(records, platform, "hosts")
    problems = _by_origin(records, platform, "problemas")
    availability = _by_origin(records, platform, "disponibilidade")
    if not (hosts or problems or availability):
        return [], [], []
    pcts = [(a["recurso"], (a.get("detalhes") or {}).get("ok_pct")) for a in availability]
    pcts = [(h, p) for h, p in pcts if isinstance(p, (int, float))]
    overall = sum(p for _, p in pcts) / len(pcts) if pcts else None
    unavailable = [h for h in hosts if h["classificacao"] == UNAVAILABLE]
    disabled = [h for h in hosts if (h.get("detalhes") or {}).get("monitorado") is False]
    active = [p for p in problems if (p.get("detalhes") or {}).get("situacao") != "resolvido"]
    severe = [p for p in active if p.get("severidade") in ("critica", "alta")]
    alarms = summary.get("alarmes_no_periodo")
    color = None if overall is None else GREEN if overall >= 99 else YELLOW if overall >= 95 else RED
    kpis = [
        _kpi("Disponibilidade geral", _pct(overall) if overall is not None else "—",
             f"média de {len(pcts)} host(s), pelo ping" if pcts else "sem histórico de ping no período", color, "activity"),
        _kpi("Ativos monitorados", str(len(hosts)), f"{len(hosts) - len(unavailable) - len(disabled)} disponíveis · "
             f"{len(unavailable)} indisponíveis · {len(disabled)} desativados", None, "monitor"),
        _kpi("Alarmes disparados", _fmt_int(alarms) if isinstance(alarms, int) else "—", "eventos de problema no período",
             YELLOW if alarms else None, "alert"),
        _kpi("Problemas ativos", str(len(active)), f"{len(severe)} de severidade alta ou desastre",
             RED if severe else YELLOW if active else GREEN, "list"),
    ]
    lowest = sorted(pcts, key=lambda x: x[1])[:8]
    observations, recommendations = [], []
    if overall is not None:
        below = [h for h, p in pcts if p < 95]
        observations.append(("green" if overall >= 99 else "yellow",
                             f"Disponibilidade geral de {_pct(overall)} no período"
                             + (f"; abaixo de 95%: {', '.join(below)}." if below else ".")))
        if below:
            recommendations.append(("media", f"{len(below)} ativo(s) com disponibilidade abaixo de 95%: {', '.join(below[:5])}.",
                                    "Investigar quedas de conectividade (link, energia, equipamento) nesses ativos."))
    if unavailable:
        observations.append(("red", f"{len(unavailable)} ativo(s) indisponível(is) agora: {_names(unavailable)}."))
        recommendations.append(("alta", f"{len(unavailable)} ativo(s) indisponível(is) no monitoramento.", "Verificar e restabelecer a comunicação."))
    if disabled:
        observations.append(("blue", f"{len(disabled)} ativo(s) com monitoramento desativado: {_names(disabled)}."))
    if active:
        top = Counter(p.get("mensagem") for p in active).most_common(3)
        observations.append(("yellow", f"{len(active)} problema(s) ativo(s); mais frequentes: "
                                       + "; ".join(f"{t} ({n})" for t, n in top) + "."))
        old = [p for p in active if (p.get("data_evento") or "9999") < (datetime.now().astimezone().isoformat()[:4] + "-01-01")]
        if old:
            recommendations.append(("media", f"{len(old)} problema(s) ativo(s) abertos desde anos anteriores.",
                                    "Revisar se ainda procedem: corrigir a causa ou ajustar o gatilho no Zabbix."))
    if isinstance(alarms, int) and hosts and alarms > 20 * len(hosts):
        recommendations.append(("baixa", f"Volume elevado de alarmes ({_fmt_int(alarms)} no período).",
                                "Revisar thresholds para reduzir ruído operacional sem perder eventos relevantes."))
    if not observations:
        observations.append(("green", "Sem pendências relevantes identificadas no período."))
    pages = [{"kind": "service", "section": "Monitoramento", "title": "Monitoramento de Infraestrutura (NOCaaS) – Visão Geral",
              "service": "NOCaaS Monitor 24x7 · Zabbix", "kpis": kpis,
              "chart_title": "Disponibilidade por Ativo (menores primeiro)",
              "chart": bars([(h, p, _pct(p)) for h, p in lowest], BLUE, 100) if lowest else
              donut([("Disponíveis", len(hosts) - len(unavailable) - len(disabled), GREEN),
                     ("Indisponíveis", len(unavailable), RED), ("Desativados", len(disabled), GREY)]),
              "legend": "", "panel_title": "Observações do Período", "panel_icon": icon("info"), "bullets": observations}]
    if active:
        rows = [{"tone": TONE.get(p["classificacao"], GREY), "a": p.get("recurso") or "—", "b": p.get("mensagem") or "—",
                 "c": SEVERITY_LABEL.get(p.get("severidade"), "—"), "d": _date(p.get("data_evento"))}
                for p in sorted(active, key=lambda p: (p["prioridade"], p.get("data_evento") or ""))[:ROWS_PER_APPENDIX_PAGE]]
        pages.append({"kind": "table", "section": "Monitoramento", "title": "Monitoramento – Problemas Ativos",
                      "service": f"{len(active)} problema(s) ativo(s) no Zabbix", "headers": ["Ativo", "Problema", "Severidade", "Desde"],
                      "rows": rows, "note": "" if len(active) <= ROWS_PER_APPENDIX_PAGE else
                      f"Mostrando {ROWS_PER_APPENDIX_PAGE} de {len(active)}; lista completa no Excel."})
    return pages, observations, recommendations


def generic_pages(platform: str, kind: str, records: list[dict[str, Any]]) -> tuple[list, list, list]:
    """Plataformas sem página própria (ex.: Sophos): indicadores por classificação e por categoria."""
    own = [r for r in records if r["plataforma"] == platform]
    if not own:
        return [], [], []
    by = Counter(r["classificacao"] for r in own)
    devices = {r["recurso"] for r in own if r["categoria"] in (ENDPOINT, HOST) and r.get("recurso")}
    alerts = [r for r in own if r["categoria"] in (SECURITY_ALERT, MONITORING_PROBLEM)]
    kpis = [_kpi("Dispositivos", str(len(devices)), "ativos coletados", None, "monitor"),
            _kpi("Alertas", str(len(alerts)), f"{sum(1 for a in alerts if a['classificacao'] != NORMAL)} exigindo atenção",
                 YELLOW if alerts else GREEN, "alert"),
            _kpi("Críticos", str(by[CRITICAL]), "itens que exigem ação", RED if by[CRITICAL] else GREEN, "shield"),
            _kpi("Indisponíveis", str(by[UNAVAILABLE]), "sem comunicação", PURPLE if by[UNAVAILABLE] else GREEN, "activity")]
    segments = [("Normal", by[NORMAL], GREEN), ("Atenção", by[ATTENTION], YELLOW), ("Crítico", by[CRITICAL], RED),
                ("Indisponível", by[UNAVAILABLE], PURPLE)]
    name = SERVICE_INFO.get(kind, ("info", kind.capitalize(), ""))[1]
    return [{"kind": "service", "section": name, "title": f"{name} – Visão Geral", "service": name, "kpis": kpis,
             "chart_title": f"Classificação dos Registros ({len(own)})", "chart": donut(segments), "legend": legend(segments),
             "panel_title": "Observações do Período", "panel_icon": icon("info"),
             "bullets": [("yellow" if by[CRITICAL] else "green",
                          f"{by[CRITICAL]} item(ns) crítico(s) e {by[ATTENTION]} em atenção.")]}], [], []


# --- montagem ------------------------------------------------------------------------------


def build_slides(data: dict[str, Any], consolidated: dict[str, Any], meta: dict[str, Any] | None,
                 company: str = "Contego Security", logo: str = "") -> dict[str, Any]:
    meta = meta or {}
    notes = meta.get("notas") or {}
    records = consolidated["registros"]
    summaries = meta.get("resumos") or {}
    client = meta.get("cliente") or data.get("titulo") or "Ambiente monitorado"
    kind = meta.get("tipo") or "Relatório Geral"
    period, period_short = meta.get("periodo") or _date(data.get("gerado_em")), meta.get("periodo_curto") or _date(data.get("gerado_em"))

    service_pages, all_recs, services = [], [], []
    for source in consolidated["fontes"]:
        platform, ptype = source["plataforma"], source["tipo"]
        builder = {"acronis": acronis_pages, "zabbix": zabbix_pages}.get(ptype)
        pages, _, recs = builder(platform, records, summaries.get(platform, {})) if builder else ([], [], [])
        if not pages:  # sem página própria para estes dados (ex.: coleta pela tela): página genérica
            pages, _, recs = generic_pages(platform, ptype, records)
        extra = (notes.get("observacoes") or {}).get(platform) or (notes.get("observacoes") or {}).get(ptype) or []
        if extra and pages:
            pages[0]["bullets"] = pages[0]["bullets"] + [("blue", str(text)) for text in extra]
        if source.get("status_coleta") == "falha":
            pages = [{"kind": "message", "section": ptype.capitalize(), "title": f"{SERVICE_INFO.get(ptype, ('', ptype, ''))[1]} – Sem dados",
                      "service": "Coleta não concluída", "text": "Não foi possível coletar os dados desta plataforma no período. "
                      "Detalhes na seção de falhas da coleta (Excel/CSV)."}]
        service_pages += pages
        all_recs += recs
        info = SERVICE_INFO.get(ptype, ("info", ptype.capitalize(), ""))
        services.append({"icon": icon(info[0], 30), "name": info[1], "subtitle": info[2]})

    for rec in notes.get("recomendacoes") or []:
        crit = str(rec.get("criticidade", "media")).lower().replace("é", "e").replace("ã", "a")
        crit = "decisao" if crit.startswith("decis") else crit if crit in CRITICALITY else "media"
        all_recs.insert(0, (crit, str(rec.get("ponto", "")), str(rec.get("acao", ""))))
    order = {"decisao": 0, "alta": 1, "media": 2, "baixa": 3}
    recommendations = [{"color": CRITICALITY[c], "label": CRITICALITY_LABEL[c], "point": p, "action": a}
                       for c, p, a in sorted(all_recs, key=lambda r: order[r[0]])]

    highlights = [{"icon": icon(h.get("icone", "check")), "title": str(h.get("titulo", "")), "text": str(h.get("texto", ""))}
                  for h in notes.get("destaques") or []]
    highlights_title = "Destaques do Mês — Principais Entregas"
    if not highlights:  # sem notas da equipe: principais achados derivados dos dados
        highlights_title = "Principais Achados do Período"
        for rec in recommendations[:6]:
            highlights.append({"icon": icon("alert" if rec["label"] == "Alta" else "info"), "title": rec["point"],
                               "text": rec["action"], "tone": rec["color"]})

    slides: list[dict[str, Any]] = [{"kind": "cover", "services": services}]
    if highlights:
        slides.append({"kind": "cards", "section": "Destaques do mês" if kind == "Relatório Mensal" else "Destaques do período",
                       "title": highlights_title,
                       "service": "Consolidado de todos os serviços", "cards": highlights[:6]})
    for note in notes.get("notas") or []:
        slides.append({"kind": "note", "section": "Nota técnica", "title": str(note.get("titulo", "Nota técnica")),
                       "service": str(note.get("servico", "")), "badge": str(note.get("selo", "")),
                       "text": str(note.get("texto", "")), "next": str(note.get("proxima_acao", ""))})
    slides += service_pages
    if notes.get("melhorias"):
        slides.append({"kind": "cards", "section": "Melhorias", "title": "Melhorias em Andamento",
                       "service": "Evolução do serviço",
                       "cards": [{"icon": icon(m.get("icone", "check")), "title": str(m.get("titulo", "")), "text": str(m.get("texto", ""))}
                                 for m in notes["melhorias"]][:6]})
    if recommendations:
        for start in range(0, len(recommendations), 7):
            slides.append({"kind": "recommendations", "section": "Recomendações", "title": "Recomendações Priorizadas",
                           "service": "Consolidado de todos os serviços", "recs": recommendations[start:start + 7]})
    priority = data.get("prioritarios") or []
    for page in range(min(APPENDIX_PAGES, math.ceil(len(priority) / ROWS_PER_APPENDIX_PAGE))):
        chunk = priority[page * ROWS_PER_APPENDIX_PAGE:(page + 1) * ROWS_PER_APPENDIX_PAGE]
        slides.append({"kind": "table", "section": "Anexo", "title": "Anexo – Itens Prioritários",
                       "service": f"{data.get('prioritarios_total', len(priority))} itens que não estão normais, do mais urgente ao menos urgente",
                       "headers": ["Ativo", "Situação", "Classificação", "Data"],
                       "rows": [{"tone": TONE.get(r["classificacao"], GREY), "a": r.get("recurso") or "—",
                                 "b": r.get("mensagem") or r.get("status") or "—",
                                 "c": data["estilos"].get(r["classificacao"], {}).get("label", r["classificacao"]),
                                 "d": _date(r.get("data_evento"))} for r in chunk],
                       "note": "Lista completa no relatório em Excel." if page == APPENDIX_PAGES - 1 or
                       (page + 1) * ROWS_PER_APPENDIX_PAGE >= len(priority) else ""})
    for number, slide in enumerate(slides, 1):
        slide["number"] = f"{number:02d}"
    return {"client": client, "kind": kind, "kind_upper": kind.upper(), "period": period, "period_short": period_short,
            "company": company, "logo": logo, "logo_icon": icon("shield", 26), "services_line": " · ".join(s["name"] for s in services),
            "slides": slides, "footer": f"{client} · {kind} — {period_short}", "generated": _date(data.get("gerado_em"))}


def logo_data_uri(path: str) -> str:
    """Logo da empresa (PNG/SVG/JPG) embutido no HTML, para o PDF não depender de arquivos externos."""
    if not path:
        return ""
    file = Path(path)
    if not file.is_file():
        return ""
    mime = mimetypes.guess_type(file.name)[0] or "image/png"
    return f"data:{mime};base64,{base64.b64encode(file.read_bytes()).decode()}"

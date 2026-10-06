"""Dados do relatório: resumo executivo, visão consolidada e seções por plataforma.

Tudo é calculado a partir do consolidado (Épico 5), para que HTML, PDF, Excel e CSV
mostrem exatamente os mesmos números.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from jervis.consolidation.model import (
    AVAILABILITY,
    BACKUP_PROTECTION,
    BACKUP_TASK,
    CLASSIFICATIONS,
    COLLECTION,
    ENDPOINT,
    HOST,
    MONITORING_PROBLEM,
    NORMAL,
    SECURITY_ALERT,
    UNAVAILABLE,
)

# Identificação visual (Feature 6.5): cor + ícone + rótulo, nunca só a cor.
CLASSIFICATION_STYLE: dict[str, dict[str, str]] = {
    "critico":      {"label": "Crítico",         "color": "#C62828", "fill": "FDE7E7", "font": "8E1B1B", "icon": "critical"},
    "indisponivel": {"label": "Indisponível",    "color": "#6A1B9A", "fill": "F1E4F7", "font": "4A126C", "icon": "unavailable"},
    "falha_coleta": {"label": "Falha de coleta", "color": "#455A64", "fill": "E6EBEE", "font": "263238", "icon": "collection"},
    "atencao":      {"label": "Atenção",         "color": "#B26A00", "fill": "FFF1D6", "font": "7A4800", "icon": "attention"},
    "normal":       {"label": "Normal",          "color": "#2E7D32", "fill": "E5F3E6", "font": "1B5E20", "icon": "normal"},
}

CATEGORY_LABEL = {
    ENDPOINT: "Dispositivos e agentes",
    SECURITY_ALERT: "Alertas e incidentes de segurança",
    BACKUP_PROTECTION: "Dispositivos protegidos",
    BACKUP_TASK: "Tarefas de backup",
    HOST: "Hosts monitorados",
    MONITORING_PROBLEM: "Problemas e alertas",
    AVAILABILITY: "Indicadores de disponibilidade",
    COLLECTION: "Falhas da coleta",
}

PLATFORM_LABEL = {"sophos": "Sophos Central", "acronis": "Acronis Cyber Protect", "zabbix": "Zabbix"}

COLLECTION_STATUS_LABEL = {"sucesso": "Coletado", "parcial": "Coleta parcial", "falha": "Sem resposta"}

DEVICE_CATEGORIES = (ENDPOINT, BACKUP_PROTECTION, HOST)
ALERT_CATEGORIES = (SECURITY_ALERT, MONITORING_PROBLEM)

# Itens que entram na lista de prioridades da visão consolidada.
PRIORITY_LIST_LIMIT = 100


def _count_by_classification(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(r["classificacao"] for r in records)
    return {c: counts[c] for c in CLASSIFICATIONS if counts[c]}


def _coverage(sources: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """Se há dados de um tipo de plataforma: um indicador zerado sem dados seria enganoso."""
    of_kind = [s for s in sources if s.get("tipo") == kind]
    silent = [s["plataforma"] for s in of_kind if s.get("status_coleta") == "falha"]
    return {
        "consultadas": len(of_kind),
        "sem_resposta": silent,
        "com_dados": len(of_kind) - len(silent) > 0,
    }


def executive_summary(consolidated: dict[str, Any]) -> dict[str, Any]:
    """Indicadores gerais (Feature 6.3)."""
    records = consolidated["registros"]
    devices_by_platform: dict[str, set[str]] = defaultdict(set)
    for r in records:
        if r["categoria"] in DEVICE_CATEGORIES and r["recurso"]:
            devices_by_platform[r["plataforma"]].add(r["recurso"].lower())
    unique_devices = set().union(*devices_by_platform.values()) if devices_by_platform else set()

    alerts = [r for r in records if r["categoria"] in ALERT_CATEGORIES]
    tasks = [r for r in records if r["categoria"] == BACKUP_TASK]
    silent = [s for s in consolidated["fontes"] if s.get("status_coleta") == "falha"]
    return {
        "dispositivos": {
            "total": len(unique_devices),
            "por_plataforma": {name: len(names) for name, names in devices_by_platform.items()},
        },
        "alertas": {"total": len(alerts), "ativos": sum(1 for r in alerts if r["classificacao"] != NORMAL)},
        "criticos": sum(1 for r in records if r["classificacao"] == "critico"),
        "backups_com_falha": sum(1 for r in tasks if (r.get("detalhes") or {}).get("situacao_backup") == "falha"),
        "backups_em_atencao": sum(1 for r in tasks if r["classificacao"] == "atencao"),
        "hosts_indisponiveis": sum(1 for r in records if r["categoria"] == HOST and r["classificacao"] == UNAVAILABLE),
        "plataformas_sem_resposta": [s["plataforma"] for s in silent],
        "plataformas_total": len(consolidated["fontes"]),
        "falhas_coleta": sum(1 for r in records if r["classificacao"] == "falha_coleta"),
        # Backups dependem da Acronis e hosts do Zabbix: sem resposta, o indicador fica "sem dados".
        "cobertura": {
            "backups": _coverage(consolidated["fontes"], "acronis"),
            "hosts": _coverage(consolidated["fontes"], "zabbix"),
        },
    }


def platform_sections(consolidated: dict[str, Any]) -> list[dict[str, Any]]:
    """Uma seção por plataforma, com seus registros agrupados por categoria (Feature 6.2)."""
    by_platform: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in consolidated["registros"]:
        by_platform[r["plataforma"]].append(r)

    sections = []
    for source in consolidated["fontes"]:
        name = source["plataforma"]
        records = by_platform.get(name, [])
        by_category: dict[str, list] = defaultdict(list)
        for r in records:
            by_category[r["categoria"]].append(r)
        # Falhas da coleta primeiro: explicam eventuais lacunas nas demais categorias.
        order = sorted(by_category, key=lambda c: (c != COLLECTION, list(CATEGORY_LABEL).index(c) if c in CATEGORY_LABEL else 99))
        sections.append({
            "nome": name,
            "tipo": source["tipo"],
            "titulo": PLATFORM_LABEL.get(source["tipo"], source["tipo"]),
            "ambiente": source.get("ambiente") or "",
            "status_coleta": source.get("status_coleta"),
            "status_label": COLLECTION_STATUS_LABEL.get(source.get("status_coleta"), source.get("status_coleta") or "—"),
            "data_coleta": source.get("data_coleta"),
            "total": len(records),
            "por_classificacao": _count_by_classification(records),
            "categorias": [
                {
                    "categoria": c,
                    "titulo": CATEGORY_LABEL.get(c, c),
                    "registros": by_category[c],
                    "por_classificacao": _count_by_classification(by_category[c]),
                }
                for c in order
            ],
        })
    return sections


def build_report_data(consolidated: dict[str, Any], title: str) -> dict[str, Any]:
    records = consolidated["registros"]
    priority = [r for r in records if r["classificacao"] != NORMAL]
    return {
        "titulo": title,
        "gerado_em": consolidated.get("gerado_em"),
        "executivo": executive_summary(consolidated),
        "resumo": consolidated["resumo"],
        "fontes": consolidated["fontes"],
        "plataformas": platform_sections(consolidated),
        "prioritarios": priority[:PRIORITY_LIST_LIMIT],
        "prioritarios_total": len(priority),
        "validacao": consolidated["validacao"],
        "categorias": CATEGORY_LABEL,
        "estilos": CLASSIFICATION_STYLE,
        "classificacoes": CLASSIFICATIONS,
        "plataforma_label": PLATFORM_LABEL,
    }

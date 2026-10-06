"""Coleta no Zabbix (frontend web 5.x–7.x): hosts, problemas e indicadores de disponibilidade.

Conjuntos coletados:
  * ``hosts`` — Monitoramento → Hosts: nome, interface/IP, status, disponibilidade;
  * ``inventario`` — Inventário → Hosts: usado para preencher o grupo dos hosts
    (a tela de hosts do Zabbix não exibe grupos);
  * ``problemas`` — Monitoramento → Problemas: ativos e histórico das últimas 24h;
  * ``disponibilidade`` — Relatórios → Relatório de disponibilidade (últimos 7 dias);
  * ``itens`` — Dados recentes (desativado por padrão): preenche a última atualização
    de cada host; pode ser pesado em ambientes grandes.

As páginas são relativas à URL do Zabbix (sem "/" inicial), funcionando também em
instalações em subdiretório (``https://servidor/zabbix/``). Endereços, rótulos de
coluna e filtros devem ser validados na versão em uso e podem ser ajustados em
``platforms.<nome>.params``.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Callable

from jervis.collectors.base import Collector, DatasetSpec
from jervis.collectors.models import CollectionResult
from jervis.collectors.parsing import parse_datetime, parse_duration, parse_percent, to_iso
from jervis.collectors.table import DEFAULT_NEXT_PAGE, TableSpec, normalize_label
from jervis.errors import ConfigError

# Paginação do Zabbix: links com seta (ícones mudaram na 7.0).
ZABBIX_NEXT_PAGE = (
    ".table-paging a:has(> .arrow-right)",
    ".table-paging a:has(> .zi-chevron-right)",
    *DEFAULT_NEXT_PAGE,
)

HOST_COLUMNS: dict[str, tuple[str, ...]] = {
    "nome": ("Name", "Nome", "Host", "Nome do host"),
    "ip": ("Interface", "Interfaces", "Endereço IP", "IP", "Address", "Endereço"),
    "grupo": ("Host groups", "Grupos de hosts", "Groups", "Grupos", "Group", "Grupo"),
    "status_monitoramento": ("Status", "Situação", "Estado"),
    "disponibilidade": ("Availability", "Disponibilidade"),
    "ultima_atualizacao": ("Last check", "Última verificação", "Última atualização", "Last update"),
}

INVENTORY_COLUMNS: dict[str, tuple[str, ...]] = {
    "host": ("Host", "Nome do host", "Name", "Nome"),
    "grupo": ("Group", "Grupo", "Host group", "Grupo de hosts"),
}

PROBLEM_COLUMNS: dict[str, tuple[str, ...]] = {
    "data_hora": ("Time", "Hora", "Horário", "Data", "Date"),
    "severidade": ("Severity", "Severidade", "Gravidade"),
    "status": ("Status", "Situação", "Estado"),
    "host": ("Host", "Hosts"),
    "descricao": ("Problem", "Problema", "Incidente", "Descrição"),
    "duracao": ("Duration", "Duração"),
    "tempo_recuperacao": ("Recovery time", "Hora de recuperação", "Tempo de recuperação"),
    "reconhecido": ("Ack", "Update", "Reconhecido", "Atualizar", "Reconhecimento"),
}

AVAILABILITY_COLUMNS: dict[str, tuple[str, ...]] = {
    "host": ("Host", "Hosts"),
    "indicador": ("Name", "Nome", "Trigger", "Gatilho"),
    "problema_pct": ("Problems", "Problemas", "Incidentes", "Problem"),
    "ok_pct": ("Ok",),
}

ITEM_COLUMNS: dict[str, tuple[str, ...]] = {
    "host": ("Host",),
    "item": ("Name", "Nome", "Item"),
    "ultima_verificacao": ("Last check", "Última verificação"),
    "ultimo_valor": ("Last value", "Último valor"),
}

# Escala de severidade do Zabbix, da mais grave para a menos grave.
SEVERITIES = ("desastre", "alta", "media", "atencao", "informacao", "nao_classificada")
_SEVERITY_WORDS = {
    "disaster": "desastre", "desastre": "desastre",
    "high": "alta", "alta": "alta",
    "average": "media", "media": "media",
    "warning": "atencao", "atencao": "atencao", "aviso": "atencao",
    "information": "informacao", "informacao": "informacao", "info": "informacao",
    "not classified": "nao_classificada", "nao classificada": "nao_classificada",
}
# Classes CSS das células de severidade (quando a coluna não traz texto).
_SEVERITY_CLASSES = {
    "disaster-bg": "desastre", "high-bg": "alta", "average-bg": "media",
    "warning-bg": "atencao", "info-bg": "informacao", "na-bg": "nao_classificada",
}

DEFAULT_MIN_AVAILABILITY = 99.0


def normalize_severity(text: str | None, classes: str = "") -> str | None:
    label = normalize_label(text or "")
    for phrase, severity in _SEVERITY_WORDS.items():
        if label == phrase or label.startswith(phrase + " "):
            return severity
    for css, severity in _SEVERITY_CLASSES.items():
        if css in classes.split():
            return severity
    return text


def availability_from(classes: str, text: str | None) -> str:
    """Disponibilidade a partir das etiquetas coloridas das interfaces (ZBX, SNMP, IPMI, JMX)."""
    tokens = classes.split()
    green, red = "status-green" in tokens, "status-red" in tokens
    if red and green or "status-yellow" in tokens:
        return "parcial"
    if red:
        return "indisponivel"
    if green:
        return "disponivel"
    label = normalize_label(text or "")
    if label in ("unavailable", "indisponivel", "down"):
        return "indisponivel"
    if label in ("available", "disponivel", "up"):
        return "disponivel"
    return "desconhecido"


def monitoring_from(text: str | None) -> bool | None:
    label = normalize_label(text or "")
    if label in ("enabled", "ativo", "ativado", "habilitado", "monitored", "monitorado"):
        return True
    if label in ("disabled", "inativo", "desativado", "desabilitado", "not monitored", "nao monitorado"):
        return False
    return None


def problem_state(text: str | None) -> str | None:
    label = normalize_label(text or "")
    if label in ("problem", "problema", "incidente"):
        return "ativo"
    if label in ("resolved", "resolvido", "ok"):
        return "resolvido"
    return None


def split_interface(text: str | None) -> tuple[str | None, str | None]:
    """'192.168.0.10:10050' → ('192.168.0.10', '10050'); '[::1]:10050' → ('::1', '10050')."""
    if not text:
        return None, None
    first = re.sub(r":\s+", ":", text.strip()).split()[0]  # várias interfaces: usa a principal (primeira)
    m = re.fullmatch(r"\[?([^\]]+?)\]?:\s*(\d+)", first)
    return (m.group(1), m.group(2)) if m else (first, None)


class ZabbixCollector(Collector):
    kind = "zabbix"
    option_names = ("min_availability",)

    def __init__(self, *args, now: Callable[[], datetime] = datetime.now, **kwargs):
        self._now = now
        super().__init__(*args, **kwargs)

    def configure(self, options: dict[str, Any]) -> None:
        target = options.get("min_availability", DEFAULT_MIN_AVAILABILITY)
        if not isinstance(target, (int, float)) or isinstance(target, bool) or not 0 < target <= 100:
            raise ConfigError(f"{self._where}.min_availability deve ser um percentual entre 0 e 100.")
        self.min_availability = float(target)

    def default_datasets(self) -> dict[str, DatasetSpec]:
        def table(columns, required, **kwargs) -> TableSpec:
            return TableSpec(columns=columns, required=required, next_page=ZABBIX_NEXT_PAGE, **kwargs)

        return {
            "hosts": DatasetSpec(
                name="hosts",
                pages={"monitoramento": "zabbix.php?action=host.view"},
                table=table(HOST_COLUMNS, ("nome",), extras=("grupo", "ultima_atualizacao"),
                            class_fields=("disponibilidade",)),
                normalize=self._normalize_host,
            ),
            "inventario": DatasetSpec(
                name="inventario",
                pages={"inventario": "hostinventories.php"},
                table=table(INVENTORY_COLUMNS, ("host", "grupo")),
            ),
            "problemas": DatasetSpec(
                name="problemas",
                pages={
                    "ativo": "zabbix.php?action=problem.view&filter_set=1&filter_show=2",
                    "historico_24h": "zabbix.php?action=problem.view&filter_set=1&filter_show=3&from=now-24h&to=now",
                },
                table=table(PROBLEM_COLUMNS, ("descricao",), extras=("tempo_recuperacao", "reconhecido"),
                            class_fields=("severidade",)),
                normalize=self._normalize_problem,
            ),
            "disponibilidade": DatasetSpec(
                name="disponibilidade",
                pages={"relatorio_7d": "report2.php?mode=0&filter_set=1&from=now-7d&to=now"},
                table=table(AVAILABILITY_COLUMNS, ("indicador", "ok_pct")),
                normalize=self._normalize_availability,
            ),
            "itens": DatasetSpec(
                name="itens",
                pages={},
                table=table(ITEM_COLUMNS, ("host", "ultima_verificacao"), extras=("ultimo_valor",)),
                normalize=self._normalize_item,
            ),
        }

    # --- normalização -----------------------------------------------------------------

    def _iso(self, text: str | None) -> str | None:
        return to_iso(parse_datetime(text, self._now(), self.date_order))

    def _normalize_host(self, row: dict[str, Any]) -> dict[str, Any]:
        interface = row.get("ip")
        ip, port = split_interface(interface)
        return {
            **row,
            "ip": ip,
            "porta": port,
            "interface": interface,
            "interfaces_monitoradas": row.get("disponibilidade"),  # ex.: "ZBX SNMP"
            "disponibilidade": availability_from(row.get("_disponibilidade_classes", ""), row.get("disponibilidade")),
            "monitorado": monitoring_from(row.get("status_monitoramento")),
            "ultima_atualizacao_iso": self._iso(row.get("ultima_atualizacao")),
        }

    def _normalize_problem(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            **row,
            "severidade": normalize_severity(row.get("severidade"), row.get("_severidade_classes", "")),
            "situacao": problem_state(row.get("status")),
            "data_hora_iso": self._iso(row.get("data_hora")),
            "duracao_segundos": parse_duration(row.get("duracao")),
        }

    def _normalize_availability(self, row: dict[str, Any]) -> dict[str, Any]:
        ok = parse_percent(row.get("ok_pct"))
        problem = parse_percent(row.get("problema_pct"))
        return {
            **row,
            "ok_pct": ok if ok is not None else row.get("ok_pct"),
            "problema_pct": problem if problem is not None else row.get("problema_pct"),
            "abaixo_da_meta": ok < self.min_availability if ok is not None else None,
        }

    def _normalize_item(self, row: dict[str, Any]) -> dict[str, Any]:
        return {**row, "ultima_verificacao_iso": self._iso(row.get("ultima_verificacao"))}

    # --- pós-processamento e destaques --------------------------------------------------

    def summarize(self, result: CollectionResult) -> None:
        hosts = result.datasets.get("hosts", [])
        self._fill_groups(hosts, result.datasets.get("inventario", []))
        self._fill_last_update(hosts, result.datasets.get("itens", []))

        highlights: dict[str, dict[str, int]] = {}
        host_issues = Counter(h["disponibilidade"] for h in hosts if h.get("monitorado") is not False)
        host_issues.pop("disponivel", None)
        unmonitored = sum(1 for h in hosts if h.get("monitorado") is False)
        if unmonitored:
            host_issues["nao_monitorado"] = unmonitored
        if host_issues:
            highlights["hosts"] = dict(host_issues)

        active = self._active_problems(result.datasets.get("problemas", []))
        by_severity = Counter(p.get("severidade") for p in active)
        ordered = {s: by_severity.pop(s) for s in SEVERITIES if s in by_severity}
        ordered.update(by_severity)  # severidades não reconhecidas, se houver
        if ordered:
            highlights["problemas"] = ordered

        availability = result.datasets.get("disponibilidade", [])
        below = [a for a in availability if a.get("abaixo_da_meta")]
        if below:
            highlights["disponibilidade"] = {"abaixo_da_meta": len(below)}

        result.summary = {
            "meta_disponibilidade_pct": self.min_availability,
            "hosts_total": len(hosts),
            "problemas_ativos_total": len(active),
            "piores_disponibilidades": [
                {"host": a.get("host"), "indicador": a.get("indicador"), "ok_pct": a.get("ok_pct")}
                for a in sorted(below, key=lambda a: a["ok_pct"])[:10]
            ],
            "destaques": highlights,
        }

    @staticmethod
    def _active_problems(problems: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # O mesmo problema pode aparecer nas origens "ativo" e "historico_24h": conta uma vez.
        seen, active = set(), []
        for p in problems:
            key = (p.get("host"), p.get("descricao"), p.get("data_hora"))
            if p.get("situacao") == "ativo" and key not in seen:
                seen.add(key)
                active.append(p)
        return active

    @staticmethod
    def _fill_groups(hosts: list[dict[str, Any]], inventory: list[dict[str, Any]]) -> None:
        groups: dict[str, set[str]] = defaultdict(set)
        for entry in inventory:
            if entry.get("host") and entry.get("grupo"):
                groups[entry["host"]].update(g.strip() for g in entry["grupo"].split(",") if g.strip())
        for host in hosts:
            if not host.get("grupo") and host.get("nome") in groups:
                host["grupo"] = ", ".join(sorted(groups[host["nome"]]))

    def _fill_last_update(self, hosts: list[dict[str, Any]], items: list[dict[str, Any]]) -> None:
        latest: dict[str, tuple[datetime, str]] = {}
        for item in items:
            when = parse_datetime(item.get("ultima_verificacao"), self._now(), self.date_order)
            name = item.get("host")
            if when and name and (name not in latest or when > latest[name][0]):
                latest[name] = (when, item["ultima_verificacao"])
        for host in hosts:
            if not host.get("ultima_atualizacao") and host.get("nome") in latest:
                when, text = latest[host["nome"]]
                host["ultima_atualizacao"] = text
                host["ultima_atualizacao_iso"] = to_iso(when)

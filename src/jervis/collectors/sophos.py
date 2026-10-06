"""Coleta no Sophos Central: dispositivos/agentes e alertas/ameaças/incidentes.

IMPORTANTE: os endereços das páginas e os rótulos das colunas abaixo são um ponto
de partida e devem ser validados no tenant real (o idioma da interface depende do
perfil do usuário, por isso há rótulos em português e inglês). Tudo pode ser
ajustado em ``platforms.<nome>.params`` sem alterar o código, por exemplo para
incluir a página de casos de ameaça (Threat Analysis Center) como outra origem
do conjunto ``alertas``.
"""

from __future__ import annotations

from typing import Any

from jervis.collectors.base import Collector, DatasetSpec
from jervis.collectors.parsing import parse_datetime, to_iso
from jervis.collectors.table import TableSpec, normalize_label

DEVICE_COLUMNS: dict[str, tuple[str, ...]] = {
    "nome": ("Nome", "Name", "Dispositivo", "Device", "Computador", "Computer", "Servidor", "Server"),
    "sistema_operacional": ("SO", "OS", "Sistema operacional", "Operating system", "Plataforma", "Platform"),
    "status_agente": ("Status do agente", "Agent status", "Integridade", "Health", "Saúde"),
    "ultima_comunicacao": (
        "Última comunicação", "Última atividade", "Last active", "Last seen", "Last online", "Visto por último",
    ),
    "situacao_protecao": ("Situação de proteção", "Status da proteção", "Protection status", "Proteção", "Protection"),
    "ip": ("IP", "Endereço IP", "IP address"),
    "ultimo_usuario": ("Último usuário", "Last user"),
    "grupo": ("Grupo", "Group"),
}

ALERT_COLUMNS: dict[str, tuple[str, ...]] = {
    "tipo": ("Tipo", "Type", "Categoria", "Category", "Descrição", "Description", "Alerta", "Alert"),
    "severidade": ("Severidade", "Severity", "Gravidade", "Prioridade", "Priority"),
    "dispositivo": ("Dispositivo", "Device", "Quem/o quê", "Who/What", "Computador", "Computer", "Endpoint"),
    "data_hora": ("Data/hora", "Date/Time", "Data e hora", "Data", "Date", "Hora", "Time", "Gerado em", "Raised"),
    "situacao": ("Situação", "Status", "Estado", "State"),
    "descricao": ("Descrição", "Description"),
}

_SEVERITY = {
    "critica": "critica", "critical": "critica",
    "alta": "alta", "high": "alta",
    "media": "media", "medium": "media",
    "baixa": "baixa", "low": "baixa",
    "informativa": "informativa", "info": "informativa", "informational": "informativa",
}


def normalize_severity(value: str | None) -> str | None:
    """Padroniza a severidade ('High', 'Severidade alta' → 'alta'); valores desconhecidos são mantidos."""
    if not value:
        return value
    for word in normalize_label(value).split():
        if word in _SEVERITY:
            return _SEVERITY[word]
    return value


class SophosCollector(Collector):
    kind = "sophos"

    def default_datasets(self) -> dict[str, DatasetSpec]:
        return {
            "dispositivos": DatasetSpec(
                name="dispositivos",
                pages={
                    "computador": "/manage/endpoint/computers-list",
                    "servidor": "/manage/server/servers-list",
                },
                table=TableSpec(columns=DEVICE_COLUMNS, required=("nome",), extras=("ip", "ultimo_usuario", "grupo")),
                normalize=self._normalize_device,
            ),
            "alertas": DatasetSpec(
                name="alertas",
                pages={"alerta": "/manage/overview/alerts"},
                table=TableSpec(columns=ALERT_COLUMNS, required=("tipo", "data_hora"), extras=("descricao",)),
                normalize=self._normalize_alert,
            ),
        }

    def _iso(self, text: str | None) -> str | None:
        return to_iso(parse_datetime(text, order=self.date_order))

    def _normalize_device(self, row: dict[str, Any]) -> dict[str, Any]:
        return {**row, "ultima_comunicacao_iso": self._iso(row.get("ultima_comunicacao"))}

    def _normalize_alert(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            **row,
            "severidade": normalize_severity(row.get("severidade")),
            "data_hora_iso": self._iso(row.get("data_hora")),
        }

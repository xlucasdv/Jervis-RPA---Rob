"""Modelo padrão de dados (Feature 5.1): um formato único para os registros das três plataformas."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# Classificação por status (Feature 5.3), da mais urgente para a menos urgente.
CRITICAL = "critico"
UNAVAILABLE = "indisponivel"
COLLECTION_FAILURE = "falha_coleta"
ATTENTION = "atencao"
NORMAL = "normal"
CLASSIFICATIONS = (CRITICAL, UNAVAILABLE, COLLECTION_FAILURE, ATTENTION, NORMAL)

# Prioridade: 1 = tratar primeiro. Crítico e indisponível dividem a prioridade máxima.
PRIORITY = {CRITICAL: 1, UNAVAILABLE: 1, COLLECTION_FAILURE: 2, ATTENTION: 3, NORMAL: 4}

# Escala comum de severidade (cada plataforma tem a sua; ver rules.py).
SEVERITIES = ("critica", "alta", "media", "baixa", "informativa")

# Categorias de registro.
ENDPOINT = "endpoint"                       # Sophos: dispositivos e agentes
SECURITY_ALERT = "alerta_seguranca"         # Sophos: alertas, ameaças, incidentes
BACKUP_PROTECTION = "protecao_backup"       # Acronis: dispositivos protegidos
BACKUP_TASK = "tarefa_backup"               # Acronis: execuções de backup
HOST = "host"                               # Zabbix: hosts monitorados
MONITORING_PROBLEM = "problema_monitoramento"  # Zabbix: problemas e eventos
AVAILABILITY = "disponibilidade"            # Zabbix: indicadores de disponibilidade
COLLECTION = "coleta"                       # falhas da própria coleta, de qualquer plataforma

REQUIRED_FIELDS = ("plataforma", "categoria", "recurso", "classificacao", "data_coleta")


@dataclass
class StandardRecord:
    plataforma: str               # nome configurado (ex.: "zabbix_hml")
    tipo_plataforma: str          # sophos | acronis | zabbix
    ambiente: str
    categoria: str
    recurso: str | None           # nome do dispositivo, host, tarefa...
    status: str | None            # status como exibido na plataforma
    severidade: str | None        # escala comum (SEVERITIES)
    classificacao: str            # CLASSIFICATIONS
    data_coleta: str | None
    data_evento: str | None = None  # ISO: alerta, último backup, última comunicação...
    mensagem: str | None = None
    observacoes: list[str] = field(default_factory=list)
    origem: str | None = None     # conjunto/página de onde veio (ex.: "alertas/alerta")
    detalhes: dict[str, Any] = field(default_factory=dict)  # registro original, para rastreabilidade
    # Identidade para remoção de duplicidades (não exportada).
    chave: tuple = field(default=(), repr=False)

    @property
    def prioridade(self) -> int:
        return PRIORITY[self.classificacao]

    @property
    def id(self) -> str:
        raw = "|".join(str(part) for part in (self.plataforma, self.categoria, *self.chave))
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "prioridade": self.prioridade,
            "classificacao": self.classificacao,
            "plataforma": self.plataforma,
            "tipo_plataforma": self.tipo_plataforma,
            "ambiente": self.ambiente,
            "categoria": self.categoria,
            "recurso": self.recurso,
            "status": self.status,
            "severidade": self.severidade,
            "mensagem": self.mensagem,
            "data_evento": self.data_evento,
            "data_coleta": self.data_coleta,
            "observacoes": self.observacoes,
            "origem": self.origem,
            "detalhes": self.detalhes,
        }

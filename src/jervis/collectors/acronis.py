"""Coleta na Acronis Cyber Protect Cloud: dispositivos protegidos e execuções de backup.

Além dos dados de tela, cada registro recebe ``situacao_backup`` e ``motivo``,
destacando backups com falha, incompletos ou desatualizados (Feature 3.4), e o
resultado traz um resumo por situação em ``summary``.

IMPORTANTE: os endereços das páginas e os rótulos das colunas abaixo são um ponto
de partida e devem ser validados no ambiente real (datacenter, idioma do perfil,
console de cliente × portal de parceiro). Tudo pode ser ajustado em
``platforms.<nome>.params`` sem alterar o código.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Callable

from jervis.collectors.base import Collector, DatasetSpec
from jervis.collectors.models import CollectionResult
from jervis.collectors.parsing import is_never, parse_datetime, parse_duration, parse_size, to_iso
from jervis.collectors.table import TableSpec, normalize_label
from jervis.errors import ConfigError

DEVICE_COLUMNS: dict[str, tuple[str, ...]] = {
    "nome": ("Nome", "Name", "Dispositivo", "Device", "Computador", "Computer", "Carga de trabalho", "Workload"),
    "status_protecao": ("Status", "Situação", "Estado", "State", "Status da proteção", "Protection status"),
    "plano_protecao": ("Plano de proteção", "Protection plan", "Plano", "Plan"),
    "ultimo_backup": ("Último backup", "Last backup", "Última execução", "Last run"),
    "proximo_backup": ("Próximo backup", "Next backup", "Próxima execução", "Next run"),
    "tipo": ("Tipo", "Type"),
    "agente": ("Agente", "Agent", "Versão do agente", "Agent version"),
}

TASK_COLUMNS: dict[str, tuple[str, ...]] = {
    "nome_tarefa": ("Tarefa", "Task", "Plano", "Plan", "Plano de proteção", "Protection plan", "Atividade", "Activity", "Nome", "Name"),
    "dispositivo": ("Dispositivo", "Device", "Carga de trabalho", "Workload", "Computador", "Computer"),
    "ultima_execucao": ("Última execução", "Last run", "Início", "Start time", "Iniciado em", "Started", "Data", "Date"),
    "status_backup": ("Status", "Resultado", "Result", "Situação", "State"),
    "duracao": ("Duração", "Duration"),
    "tamanho": ("Tamanho", "Size", "Tamanho dos dados", "Data size", "Dados copiados", "Backed up"),
    "mensagem_erro": ("Mensagem de erro", "Error message", "Mensagem", "Message", "Erro", "Error", "Detalhes", "Details"),
}

# Situações atribuídas a cada registro; "ok" não é destacado no resumo.
OK = "ok"
FAILED = "falha"
INCOMPLETE = "incompleto"
OUTDATED = "desatualizado"
WARNINGS = "com_avisos"
UNPROTECTED = "sem_protecao"
NEVER_RAN = "nunca_executado"
RUNNING = "em_execucao"
UNKNOWN = "desconhecido"

# Palavras/frases (normalizadas, sem acento) → status. A ordem define a prioridade:
# "Succeeded with warnings" é aviso, não sucesso; "Not protected" não é "protected".
_STATUS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (UNPROTECTED, ("not protected", "unprotected", "nao protegido", "sem protecao", "desprotegido")),
    (FAILED, ("failed", "failure", "error", "erro", "falha", "falhou", "critical", "critico", "critica")),
    (INCOMPLETE, ("canceled", "cancelled", "cancelado", "interrupted", "interrompido", "incomplete", "incompleto",
                  "partially", "parcialmente", "parcial", "aborted", "abortado", "stopped", "timed out")),
    (WARNINGS, ("warning", "warnings", "aviso", "avisos", "alerta", "alertas")),
    (RUNNING, ("running", "in progress", "em andamento", "em execucao", "executando", "queued", "na fila")),
    (OK, ("succeeded", "success", "successful", "sucesso", "concluido", "completed", "ok", "good", "protected", "protegido")),
)

# Expressões que contêm palavras de falha mas indicam sucesso ("Concluído sem erros").
_NEGATIONS = ("no errors", "no error", "without errors", "sem erros", "sem erro", "0 errors", "0 erros")

DEFAULT_MAX_AGE_HOURS = 26  # backup diário + folga


def classify_status(text: str | None) -> str:
    """'Succeeded with warnings' → 'com_avisos'; 'Falhou' → 'falha'; texto desconhecido → 'desconhecido'."""
    if not text:
        return UNKNOWN
    label = f" {normalize_label(text)} "
    for negation in _NEGATIONS:
        label = label.replace(f" {negation} ", " ")
    for status, phrases in _STATUS_RULES:
        if any(f" {phrase} " in label for phrase in phrases):
            return status
    return UNKNOWN


def _age(last: datetime, now: datetime) -> str:
    delta = now - last
    if delta >= timedelta(days=2):
        return f"{delta.days} dias"
    return f"{int(delta.total_seconds() // 3600)} horas"


class AcronisCollector(Collector):
    kind = "acronis"
    option_names = ("max_age_hours",)

    def __init__(self, *args, now: Callable[[], datetime] = datetime.now, **kwargs):
        self._now = now
        super().__init__(*args, **kwargs)

    def configure(self, options: dict[str, Any]) -> None:
        max_age = options.get("max_age_hours", DEFAULT_MAX_AGE_HOURS)
        if not isinstance(max_age, (int, float)) or isinstance(max_age, bool) or max_age <= 0:
            raise ConfigError(f"{self._where}.max_age_hours deve ser um número positivo (horas).")
        self.max_age = timedelta(hours=max_age)

    def default_datasets(self) -> dict[str, DatasetSpec]:
        return {
            "dispositivos": DatasetSpec(
                name="dispositivos",
                pages={"dispositivo": "/ui/#/devices/all"},
                table=TableSpec(columns=DEVICE_COLUMNS, required=("nome",), extras=("tipo", "agente")),
                normalize=self._normalize_device,
            ),
            "tarefas": DatasetSpec(
                name="tarefas",
                pages={"atividade": "/ui/#/activities"},
                table=TableSpec(columns=TASK_COLUMNS, required=("status_backup",)),
                normalize=self._normalize_task,
            ),
        }

    # --- normalização e classificação ------------------------------------------------

    def _parse_date(self, text: str | None) -> datetime | None:
        return parse_datetime(text, self._now(), self.date_order)

    def _normalize_device(self, row: dict[str, Any]) -> dict[str, Any]:
        last = self._parse_date(row.get("ultimo_backup"))
        row = {
            **row,
            "ultimo_backup_iso": to_iso(last),
            "proximo_backup_iso": to_iso(self._parse_date(row.get("proximo_backup"))),
        }
        situation, reason = self._classify_device(row, last)
        return {**row, "situacao_backup": situation, "motivo": reason}

    def _normalize_task(self, row: dict[str, Any]) -> dict[str, Any]:
        last = self._parse_date(row.get("ultima_execucao"))
        row = {
            **row,
            "ultima_execucao_iso": to_iso(last),
            "duracao_segundos": parse_duration(row.get("duracao")),
            "tamanho_bytes": parse_size(row.get("tamanho")),
        }
        situation, reason = self._classify_task(row, last)
        return {**row, "situacao_backup": situation, "motivo": reason}

    def _classify_device(self, row: dict[str, Any], last: datetime | None) -> tuple[str, str | None]:
        status_text = row.get("status_protecao")
        status = classify_status(status_text)
        if status == UNPROTECTED:
            return UNPROTECTED, f"Dispositivo sem proteção (status: {status_text})."
        if status == FAILED:
            return FAILED, f"Proteção com erro (status: {status_text})."
        if is_never(row.get("ultimo_backup")):
            return NEVER_RAN, "Nenhum backup executado até o momento."
        stale = self._staleness(last)
        if stale:
            return OUTDATED, stale
        if status == WARNINGS:
            return WARNINGS, f"Proteção com avisos (status: {status_text})."
        if status == UNKNOWN and status_text:
            return UNKNOWN, f"Status não reconhecido: {status_text}."
        return OK, None

    def _classify_task(self, row: dict[str, Any], last: datetime | None) -> tuple[str, str | None]:
        status_text = row.get("status_backup")
        status = classify_status(status_text)
        error = row.get("mensagem_erro")
        detail = f" Erro: {error}" if error else ""
        if status == FAILED:
            return FAILED, f"Backup com falha (status: {status_text}).{detail}"
        if status == INCOMPLETE:
            return INCOMPLETE, f"Backup incompleto (status: {status_text}).{detail}"
        if status == RUNNING:
            return RUNNING, None
        stale = self._staleness(last)
        if stale:
            return OUTDATED, stale
        if status == WARNINGS:
            return WARNINGS, f"Backup concluído com avisos (status: {status_text}).{detail}"
        if status == UNKNOWN:
            return UNKNOWN, f"Status não reconhecido: {status_text}." if status_text else "Status ausente."
        return OK, None

    def _staleness(self, last: datetime | None) -> str | None:
        if last is None:
            return None
        if self._now() - last > self.max_age:
            hours = self.max_age.total_seconds() / 3600
            return f"Último backup há {_age(last, self._now())} (limite: {hours:g} horas)."
        return None

    def summarize(self, result: CollectionResult) -> None:
        highlights = {}
        for name, rows in result.datasets.items():
            counts = Counter(row.get("situacao_backup") for row in rows)
            counts.pop(OK, None)
            counts.pop(None, None)
            if counts:
                highlights[name] = dict(counts.most_common())
        result.summary = {
            "limite_desatualizado_horas": self.max_age.total_seconds() / 3600,
            "destaques": highlights,
        }

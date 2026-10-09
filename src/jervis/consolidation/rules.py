"""Conversão de cada conjunto coletado para o modelo padrão e classificação por status (Feature 5.3).

Cada plataforma tem um mapeador por conjunto de dados: ele escolhe o recurso, o
status e a mensagem e decide a classificação:

  critico       — exige ação: proteção desligada, backup com falha, problema de alta severidade;
  indisponivel  — o recurso não responde: host fora do ar, endpoint sem comunicação;
  falha_coleta  — a ferramenta não conseguiu coletar (login, página, interface alterada);
  atencao       — merece acompanhamento: avisos, backup desatualizado, severidade média;
  normal        — sem problema identificado.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from jervis.collectors.table import normalize_label
from jervis.consolidation.model import (
    ACTIVITY,
    ATTENTION,
    AVAILABILITY,
    BACKUP_PROTECTION,
    BACKUP_TASK,
    COLLECTION,
    COLLECTION_FAILURE,
    CRITICAL,
    ENDPOINT,
    HOST,
    MONITORING_PROBLEM,
    NORMAL,
    SECURITY_ALERT,
    UNAVAILABLE,
    StandardRecord,
)


@dataclass(frozen=True)
class Options:
    stale_device_days: int = 7  # endpoint sem comunicação há mais tempo = indisponível
    critical_availability_pct: float = 95.0  # disponibilidade abaixo disto = crítico


@dataclass(frozen=True)
class Context:
    plataforma: str
    tipo_plataforma: str
    ambiente: str
    data_coleta: str | None
    collected_at: datetime | None
    origem: str
    options: Options


# Severidade derivada da classificação, para registros sem severidade própria.
_DERIVED_SEVERITY = {CRITICAL: "alta", UNAVAILABLE: "alta", COLLECTION_FAILURE: "alta", ATTENTION: "media", NORMAL: None}


def record(
    ctx: Context,
    categoria: str,
    recurso: str | None,
    classificacao: str,
    *,
    status: str | None = None,
    mensagem: str | None = None,
    severidade: str | None = None,
    data_evento: str | None = None,
    data_original: str | None = None,
    chave: tuple = (),
    observacoes: list[str] | None = None,
    recurso_padrao_plataforma: bool = False,
    derivar_severidade: bool = True,
) -> StandardRecord:
    notes = list(observacoes or [])
    if not recurso and recurso_padrao_plataforma:
        recurso = ctx.plataforma
        notes.append("Recurso não informado na plataforma; registro atribuído à própria plataforma.")
    if data_evento is None and data_original:
        notes.append(f"Data não reconhecida: '{data_original}'.")
    return StandardRecord(
        plataforma=ctx.plataforma,
        tipo_plataforma=ctx.tipo_plataforma,
        ambiente=ctx.ambiente,
        categoria=categoria,
        recurso=recurso,
        status=status,
        severidade=severidade if severidade is not None or not derivar_severidade else _DERIVED_SEVERITY[classificacao],
        classificacao=classificacao,
        data_coleta=ctx.data_coleta,
        data_evento=data_evento,
        mensagem=mensagem,
        observacoes=notes,
        origem=ctx.origem,
        chave=chave or (recurso,),
    )


def matches(text: str | None, phrases: tuple[str, ...]) -> bool:
    """Busca palavras/radicais no texto normalizado ('Desatualizada' casa com 'desatualizad')."""
    if not text:
        return False
    label = normalize_label(text)
    return any(re.search(rf"(?<![a-z0-9]){re.escape(p)}", label) for p in phrases)


def _older_than(iso: str | None, ctx: Context, delta: timedelta) -> int | None:
    """Dias desde ``iso`` se for mais antigo que ``delta``; senão None."""
    if not iso or not ctx.collected_at:
        return None
    try:
        when = datetime.fromisoformat(iso)
    except ValueError:
        return None
    reference = ctx.collected_at
    if when.tzinfo and reference.tzinfo is None:
        reference = reference.astimezone()
    if when.tzinfo is None and reference.tzinfo:
        when = when.astimezone()
    age = reference - when
    return age.days if age > delta else None


def _join(*parts: str | None) -> str | None:
    text = "; ".join(p for p in parts if p)
    return text or None


# --- Sophos ---------------------------------------------------------------------------

_SOPHOS_CRITICAL = (
    "not protected", "unprotected", "nao protegido", "desprotegido", "sem protecao", "bad", "ruim",
    "critical", "critico", "critica", "compromised", "comprometido", "error", "erro", "failed", "falha",
    "infected", "infectado", "malware",
)
_SOPHOS_INACTIVE = ("inactive", "inativo", "offline", "disconnected", "desconectado", "sem comunicacao", "not seen")
_SOPHOS_ATTENTION = (
    "outdated", "out of date", "desatualizad", "warning", "aviso", "atencao", "suspicious", "suspeit",
    "pending", "pendente", "reboot", "reinicializa", "needs attention", "expired", "expirad",
)
_RESOLVED = ("resolved", "resolvido", "closed", "fechado", "cleared", "concluido")


def sophos_device(row: dict[str, Any], ctx: Context) -> StandardRecord:
    agent, protection = row.get("status_agente"), row.get("situacao_protecao")
    status = _join(f"Agente: {agent}" if agent else None, f"Proteção: {protection}" if protection else None)
    last_seen = row.get("ultima_comunicacao_iso")
    common = dict(status=status, data_evento=last_seen, data_original=row.get("ultima_comunicacao"))

    if matches(protection, _SOPHOS_CRITICAL) or matches(agent, _SOPHOS_CRITICAL):
        return record(ctx, ENDPOINT, row.get("nome"), CRITICAL, mensagem=f"Proteção comprometida ({status}).", **common)
    if matches(agent, _SOPHOS_INACTIVE):
        return record(ctx, ENDPOINT, row.get("nome"), UNAVAILABLE, mensagem=f"Agente inativo ({agent}).", **common)
    days = _older_than(last_seen, ctx, timedelta(days=ctx.options.stale_device_days))
    if days is not None:
        return record(ctx, ENDPOINT, row.get("nome"), UNAVAILABLE, mensagem=f"Sem comunicação há {days} dias.", **common)
    if matches(protection, _SOPHOS_ATTENTION) or matches(agent, _SOPHOS_ATTENTION):
        return record(ctx, ENDPOINT, row.get("nome"), ATTENTION, mensagem=f"Proteção requer atenção ({status}).", **common)
    return record(ctx, ENDPOINT, row.get("nome"), NORMAL, **common)


def sophos_alert(row: dict[str, Any], ctx: Context) -> StandardRecord:
    severity = row.get("severidade")
    notes = []
    if matches(row.get("situacao"), _RESOLVED):
        classification = NORMAL
    elif severity in ("critica", "alta"):
        classification = CRITICAL
    elif severity in ("media", "baixa"):
        classification = ATTENTION
    elif severity == "informativa":
        classification = NORMAL
    else:
        classification = ATTENTION
        notes.append(
            f"Severidade não reconhecida: '{severity}'; classificado como atenção por precaução." if severity
            else "Severidade não informada; classificado como atenção por precaução."
        )
    return record(
        ctx, SECURITY_ALERT, row.get("dispositivo"), classification,
        status=row.get("situacao"), mensagem=row.get("tipo") or row.get("descricao"),
        severidade=severity if severity in ("critica", "alta", "media", "baixa", "informativa") else None,
        data_evento=row.get("data_hora_iso"), data_original=row.get("data_hora"),
        chave=(row.get("dispositivo"), row.get("tipo"), row.get("data_hora")),
        observacoes=notes, recurso_padrao_plataforma=True, derivar_severidade=False,
    )


# --- Acronis --------------------------------------------------------------------------

_BACKUP_CLASSIFICATION = {
    "falha": CRITICAL, "sem_protecao": CRITICAL, "nunca_executado": CRITICAL,
    "incompleto": ATTENTION, "desatualizado": ATTENTION, "com_avisos": ATTENTION, "desconhecido": ATTENTION,
    "em_execucao": NORMAL, "ok": NORMAL,
}


def _backup_classification(row: dict[str, Any]) -> tuple[str, list[str]]:
    situation = row.get("situacao_backup")
    if situation in _BACKUP_CLASSIFICATION:
        return _BACKUP_CLASSIFICATION[situation], []
    return ATTENTION, [f"Situação de backup não reconhecida: '{situation}'."]


def acronis_device(row: dict[str, Any], ctx: Context) -> StandardRecord:
    classification, notes = _backup_classification(row)
    return record(
        ctx, BACKUP_PROTECTION, row.get("nome"), classification,
        status=row.get("status_protecao"), mensagem=row.get("motivo"),
        data_evento=row.get("ultimo_backup_iso"),
        data_original=None if row.get("situacao_backup") == "nunca_executado" else row.get("ultimo_backup"),
        observacoes=notes,
    )


def acronis_task(row: dict[str, Any], ctx: Context) -> StandardRecord:
    classification, notes = _backup_classification(row)
    task, device = row.get("nome_tarefa"), row.get("dispositivo")
    message = row.get("motivo") or (f"{task}: {row.get('status_backup')}" if task else row.get("status_backup"))
    return record(
        ctx, BACKUP_TASK, device or task, classification,
        status=row.get("status_backup"), mensagem=message,
        data_evento=row.get("ultima_execucao_iso"), data_original=row.get("ultima_execucao"),
        chave=(device, task, row.get("ultima_execucao")), observacoes=notes,
    )


# --- Acronis por API (conjuntos maquinas, alertas, atividades) --------------------------

_ACRONIS_SECURITY_CATEGORIES = ("url filtering", "antimalware", "detection and response", "device control",
                                "vulnerability", "patch", "email")
_ACRONIS_SEVERITY = {"critical": "critica", "error": "alta", "warning": "media", "information": "informativa"}


NO_BACKUP_PLAN, STALE_BACKUP = "Sem plano de backup.", "Backup desatualizado."


def acronis_machine(row: dict[str, Any], ctx: Context) -> StandardRecord:
    status, label = row.get("status"), row.get("status_label") or row.get("status")
    notes = [] if row.get("tem_backup") else [NO_BACKUP_PLAN]
    backup_problem = None
    if row.get("tem_backup"):
        last = row.get("ultimo_backup_iso")
        days = _older_than(last, ctx, timedelta(days=ctx.options.stale_device_days))
        if not last:
            backup_problem = "Plano de backup aplicado, mas nenhum backup concluído"
        elif days is not None:
            backup_problem = f"Último backup há {days} dias"
        if backup_problem:
            notes.append(STALE_BACKUP)
    if backup_problem:
        classification, message = CRITICAL, backup_problem
    elif status in ("critical", "error", "not_protected"):
        classification, message = CRITICAL, {"critical": "Proteção em estado crítico", "error": "Plano de proteção com erro",
                                             "not_protected": "Máquina não protegida"}[status]
    elif row.get("online") is False:
        classification, message = UNAVAILABLE, "Máquina offline"
    elif status in ("warning", "no_policies_applied"):
        classification, message = ATTENTION, label
    else:
        classification, message = NORMAL, None
    status_text = _join(label, "online" if row.get("online") else "offline" if row.get("online") is False else None)
    return record(
        ctx, ENDPOINT, row.get("nome"), classification, status=status_text,
        mensagem=_join(message, f"Planos: {row['planos']}" if row.get("planos") else None),
        data_evento=row.get("ultimo_backup_iso"), observacoes=notes, chave=(row.get("id") or row.get("nome"),),
    )


def acronis_alert(row: dict[str, Any], ctx: Context) -> StandardRecord:
    severity = row.get("severidade")
    category = SECURITY_ALERT if matches(row.get("categoria"), _ACRONIS_SECURITY_CATEGORIES) else MONITORING_PROBLEM
    notes = []
    if row.get("mitigado"):
        classification = NORMAL
        notes.append("Ameaça mitigada.")
    elif severity == "critical":
        classification = CRITICAL
    elif severity in ("error", "warning"):
        classification = ATTENTION
    elif severity == "information":
        classification = NORMAL
    else:
        classification = ATTENTION
        notes.append(f"Severidade não reconhecida: '{severity}'.")
    return record(
        ctx, category, row.get("dispositivo"), classification,
        status=row.get("categoria"), mensagem=_join(row.get("titulo"), row.get("detalhe")),
        severidade=_ACRONIS_SEVERITY.get(severity), data_evento=row.get("data_hora_iso"),
        chave=(row.get("dispositivo"), row.get("tipo"), row.get("data_hora_iso")),
        observacoes=notes, recurso_padrao_plataforma=True, derivar_severidade=False,
    )


def acronis_activity(row: dict[str, Any], ctx: Context) -> StandardRecord:
    result = row.get("resultado")
    if result in ("error", "timedout", "abandoned"):
        classification = ATTENTION
    elif result == "warning":
        classification = ATTENTION
    else:  # ok, cancelado ou em andamento
        classification = NORMAL
    return record(
        ctx, ACTIVITY, row.get("dispositivo"), classification,
        status=row.get("resultado_label"), mensagem=_join(row.get("titulo"), row.get("erro")),
        data_evento=row.get("fim_iso") or row.get("inicio_iso"),
        chave=(row.get("dispositivo"), row.get("tipo"), row.get("inicio_iso")), recurso_padrao_plataforma=True,
    )


# --- Zabbix ---------------------------------------------------------------------------

_ZABBIX_SEVERITY = {
    "desastre": "critica", "alta": "alta", "media": "media", "atencao": "baixa", "informacao": "informativa",
}


def zabbix_host(row: dict[str, Any], ctx: Context) -> StandardRecord:
    availability, monitored = row.get("disponibilidade"), row.get("monitorado")
    status = _join(row.get("status_monitoramento"), f"disponibilidade: {availability}" if availability else None)
    notes = []
    if monitored is False:
        classification, message = ATTENTION, "Host não monitorado (desativado no Zabbix)."
    elif availability == "indisponivel":
        classification, message = UNAVAILABLE, f"Host indisponível (interfaces: {row.get('interfaces_monitoradas')})."
    elif availability == "parcial":
        classification, message = ATTENTION, f"Parte das interfaces indisponível ({row.get('interfaces_monitoradas')})."
    else:
        classification, message = NORMAL, None
        if availability != "disponivel":
            notes.append("Disponibilidade desconhecida (interface ainda não verificada ou sem interface).")
    return record(
        ctx, HOST, row.get("nome"), classification, status=status, mensagem=message,
        data_evento=row.get("ultima_atualizacao_iso"), data_original=row.get("ultima_atualizacao"), observacoes=notes,
    )


def zabbix_problem(row: dict[str, Any], ctx: Context) -> StandardRecord:
    severity = _ZABBIX_SEVERITY.get(row.get("severidade"))
    notes = []
    situation = row.get("situacao")
    if situation is None:
        notes.append(f"Status do problema não reconhecido: '{row.get('status')}'; tratado como ativo.")
    if situation == "resolvido":
        classification = NORMAL
    elif severity in ("critica", "alta"):
        classification = CRITICAL
    elif severity in ("media", "baixa"):
        classification = ATTENTION
    elif severity == "informativa":
        classification = NORMAL
    else:
        classification = ATTENTION
        notes.append("Problema sem severidade definida; classificado como atenção por precaução.")
    return record(
        ctx, MONITORING_PROBLEM, row.get("host"), classification,
        status=row.get("status"), mensagem=row.get("descricao"), severidade=severity,
        data_evento=row.get("data_hora_iso"), data_original=row.get("data_hora"),
        chave=(row.get("host"), row.get("descricao"), row.get("data_hora")),
        observacoes=notes, recurso_padrao_plataforma=True, derivar_severidade=False,
    )


def zabbix_availability(row: dict[str, Any], ctx: Context) -> StandardRecord:
    ok, indicator = row.get("ok_pct"), row.get("indicador")
    notes = []
    if not isinstance(ok, (int, float)) or not 0 <= ok <= 100:
        classification, message = ATTENTION, f"{indicator}: valor de disponibilidade inconsistente ({ok!r})."
        notes.append(f"Percentual de disponibilidade inválido: {ok!r}.")
    else:
        message = f"{indicator}: {ok:g}% disponível."
        if ok < ctx.options.critical_availability_pct:
            classification = CRITICAL
        elif row.get("abaixo_da_meta"):
            classification = ATTENTION
        else:
            classification = NORMAL
    return record(
        ctx, AVAILABILITY, row.get("host"), classification,
        status=f"{ok}% ok" if ok is not None else None, mensagem=message,
        chave=(row.get("host"), indicator), observacoes=notes, recurso_padrao_plataforma=True,
    )


# --- falhas da coleta -----------------------------------------------------------------


def collection_issue(issue: dict[str, Any], ctx: Context) -> StandardRecord:
    is_error = issue.get("severity") == "erro"
    return record(
        ctx, COLLECTION, f"{ctx.plataforma}: {issue.get('stage')}", COLLECTION_FAILURE if is_error else ATTENTION,
        status=issue.get("category"), mensagem=issue.get("message"),
        severidade="alta" if is_error else "baixa", data_evento=issue.get("timestamp"),
        chave=(issue.get("stage"), issue.get("category"), issue.get("message")),
        observacoes=[f"Captura de tela: {issue['screenshot']}"] if issue.get("screenshot") else [],
    )


Mapper = Callable[[dict[str, Any], Context], StandardRecord]

MAPPERS: dict[tuple[str, str], Mapper] = {
    ("sophos", "dispositivos"): sophos_device,
    ("sophos", "alertas"): sophos_alert,
    ("acronis", "dispositivos"): acronis_device,
    ("acronis", "tarefas"): acronis_task,
    ("acronis", "maquinas"): acronis_machine,
    ("acronis", "alertas"): acronis_alert,
    ("acronis", "atividades"): acronis_activity,
    ("zabbix", "hosts"): zabbix_host,
    ("zabbix", "problemas"): zabbix_problem,
    ("zabbix", "disponibilidade"): zabbix_availability,
}

# Conjuntos usados só para enriquecer outros (já cruzados na coleta): não viram registros.
AUXILIARY_DATASETS = frozenset({("zabbix", "inventario"), ("zabbix", "itens")})

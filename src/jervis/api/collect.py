"""Coleta por API de um cliente: transforma as respostas de cada plataforma em ``CollectionResult``.

Os conjuntos produzidos são consolidados pelas regras de ``jervis.consolidation.rules`` (MAPPERS) e viram os
mesmos relatórios (HTML, PDF, Excel, CSV) da coleta tradicional.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from jervis.api import ApiError
from jervis.collectors.models import WARNING, CollectionResult, Issue, now_iso
from jervis.errors import IssueCategory

# --- Acronis ------------------------------------------------------------------------

# Tipos de alerta do Acronis → título como aparece no console em português.
ACRONIS_ALERT_TITLES = {
    "CpsURLfBrowserExtensionConnectionError": "Não foi possível conectar à extensão de filtro de URL do navegador",
    "PMInstallationFailed": "Falha na instalação do patch",
    "MachineOffline30": "Máquina offline há mais de 30 dias",
    "MachineOffline20": "Máquina offline há mais de 20 dias",
    "MiMonitoringLowDiskSpace": "Pouco espaço em disco",
    "MiMonitoringMetricGatheringFailed": "Falha na coleta de dados de monitoramento",
    "PeripheralDeviceAccessBlocked": "Acesso a dispositivo periférico bloqueado",
    "MiMonitoringHardwareComponentReplaced": "Componente de hardware substituído",
    "MiMonitoringHardwareComponentAdded": "Componente de hardware adicionado",
    "MiMonitoringHardwareComponentRemoved": "Componente de hardware removido",
    "MiMonitoringWorkloadRequiresRestart": "Reinicialização necessária",
    "AcroinstRebootRequiredSuccessfulLocalInstall": "Reinicialização necessária para concluir a instalação do agente",
    "ProtectionServiceNotWorking": "Serviço de proteção (Active Protection) não está respondendo",
    "EDRIncidentDetected": "Incidente detectado (EDR)",
    "TotalProtectDeniedCategoryURLDetected": "URL bloqueada por categoria",
    "MaliciousUrlBlocked": "URL maliciosa bloqueada",
    "QuarantineFailed": "Falha na ação de quarentena",
    "ActiveProtectionServiceFailedToUninstall": "Falha ao desinstalar o Active Protection",
    "AcroinstNotEnoughDiskSpaceLocalInstall": "Instalação do agente falhou por falta de espaço",
    "MiMonitoringCPUOverheating": "Superaquecimento da CPU",
    "MiMonitoringHighMemoryUsage": "Alto uso de memória",
    "BackupFailed": "Falha no backup",
    "BackupDidNotStart": "Backup não iniciado",
    "NoBackupForXDays": "Sem backup há vários dias",
}

ACRONIS_ACTIVITY_TITLES = {
    "UpdateVapm": "Atualizar definições de proteção",
    "UserPatchInstallation": "Instalação de patch (solicitada)",
    "SystemPatchInstallation": "Instalação de patch (agendada)",
    "AutoUpdateStandby": "Atualização automática do agente",
    "Download": "Download de componentes",
    "DownloadInstaller": "Download do instalador",
    "UpdateAgent": "Atualizar o agente",
    "WinScan": "Verificar vulnerabilidades no Windows",
    "TpScan": "Verificar vulnerabilidades em aplicativos de terceiros",
    "AntimalwareScan": "Verificação de malware",
    "Backup": "Backup",
}

_RESULT_LABEL = {"ok": "Concluído", "error": "Erro", "warning": "Concluído com avisos", "cancelled": "Cancelado",
                 "abandoned": "Abandonado", "timedout": "Tempo esgotado"}
_MACHINE_STATUS_LABEL = {"ok": "OK", "idle": "OK", "running": "Em execução", "warning": "Aviso", "error": "Erro",
                         "critical": "Crítico", "no_policies_applied": "Sem plano aplicado", "not_protected": "Não protegido"}


def local_iso(value: Any) -> str | None:
    """'2026-10-08T15:29:59.428886469Z' → '2026-10-08T12:29:59-03:00' (fuso desta máquina)."""
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    match = re.match(r"^(.*?T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", text)
    if match:  # Python aceita no máximo 6 casas de fração de segundo
        text = match.group(1) + (match.group(2) or "")[:7] + match.group(3)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone().isoformat(timespec="seconds")


def humanize(code: str) -> str:
    """'MiMonitoringLowDiskSpace' → 'Mi monitoring low disk space' (para tipos sem tradução)."""
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", code.split("~")[-1]).replace("_", " ").strip()
    return words[:1].upper() + words[1:].lower() if words else code


def _attr(context: dict[str, Any], group: str, key: str) -> Any:
    for attribute in context.get("attributes") or []:
        if attribute.get("name") == group:
            for kv in attribute.get("kvs") or []:
                if kv.get("key") == key:
                    return kv.get("value")
    return None


def acronis_machine_row(item: dict[str, Any]) -> dict[str, Any]:
    ctx, agg = item.get("context") or {}, item.get("aggregate") or {}
    policies = item.get("policies") or []
    backups = [p for p in policies if "backup" in (p.get("type") or "")]
    last_backup = max((p.get("last_success_run") for p in backups if p.get("last_success_run")), default=None)
    online = _attr(ctx, "agent", "is_online")
    status = agg.get("status")
    return {
        "nome": ctx.get("user_defined_name") or ctx.get("name"),
        "status": status,
        "status_label": _MACHINE_STATUS_LABEL.get(status, status),
        "planos": agg.get("names") or "",
        "online": None if online is None else bool(online),
        "sistema": _attr(ctx, "agent", "os_name"),
        "versao_agente": _attr(ctx, "agent", "version"),
        "cyberfit": _attr(ctx, "cyberfit", "cyberfit_score_value"),
        "conta": ctx.get("tenant_name"),
        "tem_backup": bool(backups),
        "ultimo_backup_iso": local_iso(last_backup),
        "id": ctx.get("id"),
    }


def acronis_alert_row(alert: dict[str, Any]) -> dict[str, Any]:
    details = alert.get("details") or {}
    kind = alert.get("type") or ""
    def text(key):  # o Acronis às vezes manda um objeto técnico no lugar do texto: só texto vira detalhe
        value = details.get(key)
        return value if isinstance(value, str) and value.strip() else None

    detail = (text("errorMessage") or text("url") or text("incidentTrigger")
              or (f"{details.get('drive_name')}: {details.get('remaining_space_value')}{details.get('remaining_space_unit') or ''} livres"
                  if details.get("drive_name") else None)
              or (f"offline há {details['daysPassed']} dias" if isinstance(details.get("daysPassed"), int) else None)
              or text("information"))
    return {
        "data_hora_iso": local_iso(alert.get("createdAt")),
        "severidade": alert.get("severity"),
        "tipo": kind,
        "titulo": ACRONIS_ALERT_TITLES.get(kind, humanize(kind)),
        "categoria": alert.get("category"),
        "dispositivo": details.get("resourceName") or details.get("workload_name"),
        "plano": details.get("planName") or details.get("plan_name"),
        "detalhe": str(detail) if detail is not None else None,
        "mitigado": details.get("isMitigated") == "true" if "isMitigated" in details else None,
        "link": details.get("redirectLink"),
    }


def acronis_activity_row(activity: dict[str, Any]) -> dict[str, Any]:
    result = activity.get("result") or {}
    error = result.get("error") or {}
    context = error.get("context") or {}
    kind = activity.get("type") or ""
    return {
        "tipo": kind,
        "titulo": ACRONIS_ACTIVITY_TITLES.get(kind, humanize(kind)),
        "dispositivo": (activity.get("resource") or {}).get("name"),
        "estado": activity.get("state"),
        "resultado": result.get("code"),
        "resultado_label": _RESULT_LABEL.get(result.get("code"), activity.get("state")),
        "erro": context.get("errMsg") or error.get("reason") or (context.get("reason") if error else None),
        "inicio_iso": local_iso(activity.get("startedAt") or activity.get("createdAt")),
        "fim_iso": local_iso(activity.get("completedAt")),
        "iniciado_por": activity.get("startedByUser"),
    }


@dataclass(frozen=True)
class Period:
    """Período analisado: [since, until) com fuso."""

    since: datetime
    until: datetime
    label: str  # "Julho de 2026" ou "Últimos 7 dias"
    short: str  # "Julho/2026" ou "últimos 7 dias"
    monthly: bool = False

    def contains(self, iso: str | None) -> bool:
        if not iso:
            return False
        try:
            moment = datetime.fromisoformat(iso)
        except ValueError:
            return False
        return self.since <= moment < self.until


MONTHS = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro",
          "Novembro", "Dezembro"]


def last_days(days: int, now: datetime | None = None) -> Period:
    now = (now or datetime.now()).astimezone()
    return Period(now - timedelta(days=days), now, f"Últimos {days} dias", f"últimos {days} dias")


def month(text: str | None = None, now: datetime | None = None) -> Period:
    """'2026-07' → julho de 2026, do dia 1 às 00:00 até o dia 1 do mês seguinte (fuso local).

    Sem texto: o mês atual. Mês ainda em andamento termina agora ("Outubro de 2026 (até 08/10)").
    """
    now = (now or datetime.now()).astimezone()
    text = text or f"{now:%Y-%m}"
    match = re.fullmatch(r"(\d{4})-(\d{2})", text.strip())
    if not match or not 1 <= int(match.group(2)) <= 12:
        raise ValueError("Use o formato AAAA-MM (ex.: 2026-07).")
    year, number = int(match.group(1)), int(match.group(2))
    since = datetime(year, number, 1).astimezone()
    if since > now:
        raise ValueError(f"{text} ainda não começou.")
    until = datetime(year + (number == 12), number % 12 + 1, 1).astimezone()
    name = MONTHS[number - 1]
    if until > now:  # mês em andamento: até agora
        return Period(since, now, f"{name} de {year} (até {now:%d/%m})", f"{name}/{year}", monthly=True)
    return Period(since, until, f"{name} de {year}", f"{name}/{year}", monthly=True)


def collect_acronis(api, platform: str, customer_name: str, period: Period | None = None,
                    environment: str = "") -> CollectionResult:
    period = period or last_days(7)
    result = CollectionResult(platform=platform, kind="acronis", environment=environment)
    try:
        tenant = api.customer_tenant(customer_name)
    except ApiError as exc:
        result.issues.append(_issue("cliente", exc))
        result.finished_at = now_iso()
        return result
    session = api.for_customer(tenant["id"])
    since = period.since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    steps = (("maquinas", session.machines, acronis_machine_row, False),
             ("alertas", lambda: api.alerts(tenant["id"]), acronis_alert_row, True),
             ("atividades", lambda: session.activities(since), acronis_activity_row, True))
    for name, fetch, to_row, in_period in steps:
        try:
            rows = [to_row(item) for item in fetch()]
        except ApiError as exc:
            result.issues.append(_issue(name, exc))
            continue
        if in_period:  # alertas e atividades: só os do período analisado
            rows = [r for r in rows if period.contains(r.get("data_hora_iso") or r.get("inicio_iso"))]
        result.datasets[name] = rows
    machines = result.datasets.get("maquinas", [])
    result.summary = {
        "cliente_na_plataforma": tenant.get("name"),
        "periodo": period.label,
        "maquinas_sem_backup": sum(1 for m in machines if not m["tem_backup"]),
        "maquinas_offline": sum(1 for m in machines if m["online"] is False),
    }
    indicators, warnings = acronis_indicators(session, period)
    result.summary["indicadores"] = indicators
    result.issues += warnings
    if machines and all(not m["tem_backup"] for m in machines):
        result.issues.append(Issue("maquinas", IssueCategory.INCOMPLETE_DATA,
                                   "Nenhuma máquina do cliente tem plano de backup no Acronis.", severity=WARNING))
    result.finished_at = now_iso()
    return result


SEVERITIES = ("critical", "high", "medium", "low", "none")


def acronis_indicators(session, period: Period) -> tuple[dict[str, Any], list[Issue]]:
    """Indicadores do painel do Acronis (EDR, vulnerabilidades, patches, sessões remotas).

    A maior parte vem da API interna do console (não documentada; ver CustomerSession.playbook): cada leitura é
    isolada e, se falhar, vira aviso e o indicador fica ausente, nunca estimado.
    """
    since, until = int(period.since.timestamp()), int(period.until.timestamp())
    indicators: dict[str, Any] = {"fontes": {}}
    warnings: list[Issue] = []

    def read(name: str, source: str, fetch):
        try:
            indicators[name] = fetch()
            indicators["fontes"][name] = source
        except ApiError as exc:
            if exc.status == 403 and "Feature not available" in str(exc):  # recurso fora da licença do cliente
                warnings.append(Issue(f"indicadores/{name}", IssueCategory.INCOMPLETE_DATA,
                                      f"{name}: recurso não licenciado para este cliente no Acronis (indicador fora do relatório).",
                                      severity=WARNING))
                return
            where = "API interna do console (não documentada)" if source == "api_interna" else "API"
            warnings.append(Issue(f"indicadores/{name}", IssueCategory.UNAVAILABLE,
                                  f"{name}: não foi possível ler pela {where}: {exc}", severity=WARNING))

    def protection():
        raw = session.protection_status()
        return {"gerenciados": raw.get("managed", 0), "descobertos": raw.get("discovered", 0),
                "protegidos": raw.get("protected", 0), "desprotegidos": raw.get("unprotected", 0)}

    def threats():
        raw = session.threat_status()
        auto, manual, pending = raw.get("auto", 0), raw.get("manual", 0), raw.get("not_mitigated", 0)
        return {"total": auto + manual + pending, "automaticas": auto, "manuais": manual, "nao_mitigadas": pending,
                "observacao": "situação atual do painel do Acronis (a rota não aceita período)"}

    def tactics():
        return [{"mitre_id": t.get("mitre_id"), "nome": t.get("name"), "contagem": int(t.get("count") or 0),
                 "anterior": int(t.get("count_prev") or 0)} for t in session.tactics(since, until)]

    def incidents():
        rows = [i for i in session.incidents() if period.contains(local_iso(i.get("created_at")))]
        mitigation = {"AUTO_MITIGATED": "automaticos", "MITIGATED": "manuais"}
        by = {"automaticos": 0, "manuais": 0, "nao_mitigados": 0}
        for i in rows:
            by[mitigation.get(i.get("mitigation_state"), "nao_mitigados")] += 1
        categories: dict[str, int] = {}
        for i in rows:
            for c in i.get("incident_categories") or []:
                categories[c] = categories.get(c, 0) + 1
        return {"total": len(rows), **by, "em_investigacao": sum(1 for i in rows if i.get("state") != "CLOSED"),
                "por_categoria": categories, "maquinas": sorted({i.get("host_name") for i in rows if i.get("host_name")}),
                "severidade_alta": sum(1 for i in rows if i.get("severity") in ("HIGH", "CRITICAL"))}

    def vulnerable_machines():
        raw = session.vulnerable_machines()
        return {k: raw.get(k, 0) for k in (*SEVERITIES, "protected")} | {k: v for k, v in raw.items() if k not in SEVERITIES}

    def vulnerabilities():
        rows = session.vulnerabilities()
        by = {k: 0 for k in SEVERITIES}
        products: dict[str, dict[str, Any]] = {}
        for v in rows:
            severity = v.get("severity") or "none"
            by[severity] = by.get(severity, 0) + 1
            if severity == "critical":
                entry = products.setdefault(v.get("product_name") or "?", {"produto": v.get("product_name"), "fornecedor": v.get("vendor"),
                                                                            "criticas": 0, "cves": {}, "maquinas": set()})
                entry["criticas"] += 1
                entry["cves"][v.get("cve")] = max(entry["cves"].get(v.get("cve"), 0), v.get("score") or 0)
                entry["maquinas"].add(v.get("resource_name"))
        top = sorted(products.values(), key=lambda e: -e["criticas"])[:8]
        return {"total": len(rows), "por_severidade": by, "maquinas_afetadas": len({v.get("resource_name") for v in rows}),
                "produtos_criticos": [{"produto": e["produto"], "fornecedor": e["fornecedor"], "criticas": e["criticas"],
                                       "maquinas": len(e["maquinas"]),
                                       "cves": [c for c, _ in sorted(e["cves"].items(), key=lambda x: -x[1])[:3]]} for e in top]}

    def missing():
        raw = session.missing_updates()
        return {"seguranca": raw.get("security", 0), "criticas": raw.get("critical", 0), "outras": raw.get("other", 0),
                "total": sum(raw.values())}

    def patches():
        raw = session.patch_installs(since, until)
        machines, updates = raw["maquinas"], raw["atualizacoes"]
        return {"maquinas_instaladas": machines.get("installed", 0), "maquinas_com_falha": machines.get("failed", 0),
                "maquinas_reinicio_pendente": machines.get("reboot_required", 0),
                "atualizacoes_instaladas": updates.get("installed", 0), "atualizacoes_com_falha": updates.get("failed", 0)}

    def summary():
        raw = session.protection_summary(since, until)
        return {"urls_maliciosas_bloqueadas": raw.get("malicious_urls_blocked"), "perifericos_bloqueados": raw.get("blocked_peripheral_devices"),
                "ameacas_mitigadas": raw.get("mitigated_threats"), "patches_instalados": raw.get("installed_patches"),
                "vulnerabilidades_corrigidas": raw.get("patched_vulnerabilities")}

    def sessions():
        rows = session.remote_sessions(since, until)
        by_user: dict[str, int] = {}
        for r in rows:
            by_user[r.get("accessed_by") or "?"] = by_user.get(r.get("accessed_by") or "?", 0) + 1
        return {"total": len(rows), "por_usuario": dict(sorted(by_user.items(), key=lambda x: -x[1]))}

    read("protecao", "api_interna", protection)
    read("ameacas", "api_interna", threats)
    read("taticas", "api_interna", tactics)
    read("incidentes_edr", "api_publica", incidents)
    read("maquinas_vulneraveis", "api_interna", vulnerable_machines)
    read("vulnerabilidades", "api_interna", vulnerabilities)
    read("atualizacoes_faltantes", "api_interna", missing)
    read("patches", "api_interna", patches)
    read("sessoes_remotas", "api_interna", sessions)
    read("resumo_periodo", "api_interna", summary)
    return indicators, warnings


# --- Sophos Central --------------------------------------------------------------------

SOPHOS_HEALTH = {"good": "Bom", "suspicious": "Suspeito", "bad": "Ruim", "unknown": "Desconhecido"}
SOPHOS_SEVERITY = {"high": "alta", "medium": "media", "low": "baixa"}
SOPHOS_ALERT_STATUS = {"open": "Aberto", "resolved": "Resolvido", "closed": "Fechado"}
SOPHOS_PRODUCT = {"endpoint": "Endpoint", "server": "Servidor", "firewall": "Firewall", "mobile": "Mobile", "email": "E-mail",
                  "wireless": "Wireless", "ztna": "ZTNA", "xgEmail": "E-mail", "iaas": "Nuvem"}


def sophos_endpoint_row(item: dict[str, Any]) -> dict[str, Any]:
    health, os_ = item.get("health") or {}, item.get("os") or {}
    overall = health.get("overall")
    threats, services = (health.get("threats") or {}).get("status"), (health.get("services") or {}).get("status")
    isolation = item.get("isolation") or {}
    protection = "; ".join(f"{label}: {SOPHOS_HEALTH.get(value, value)}" for label, value in
                           (("Ameaças", threats), ("Serviços", services)) if value)
    return {
        "id": item.get("id"),
        "nome": item.get("hostname"),
        "tipo": "Servidor" if item.get("type") == "server" or os_.get("isServer") else "Computador",
        "sistema_operacional": (os_.get("name") or os_.get("platform") or "").strip() or None,
        "online": item.get("online"),
        "status_agente": SOPHOS_HEALTH.get(overall, overall),
        "situacao_protecao": protection or None,
        "saude": overall, "saude_ameacas": threats, "saude_servicos": services,
        "ultima_comunicacao": item.get("lastSeenAt"),
        "ultima_comunicacao_iso": local_iso(item.get("lastSeenAt")),
        "ip": ", ".join(item.get("ipv4Addresses") or []) or None,
        "ultimo_usuario": (item.get("associatedPerson") or {}).get("viaLogin") or (item.get("associatedPerson") or {}).get("name"),
        "grupo": (item.get("group") or {}).get("name"),
        "protecao_adulteracao": item.get("tamperProtectionEnabled"),
        "isolado": isolation.get("status") == "isolated" if isolation else None,
        "produtos": ", ".join(f"{p.get('code')} {p.get('version') or ''}".strip() for p in item.get("assignedProducts") or []) or None,
    }


# Caracteres de controle (ex.: trecho binário de certificado na descrição de alerta do firewall): o Excel recusa
# e sujam o HTML/PDF; tab e quebra de linha ficam
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean_text(value: Any) -> Any:
    return CONTROL_CHARS.sub("", value).strip() if isinstance(value, str) else value


def sophos_alert_row(alert: dict[str, Any]) -> dict[str, Any]:
    severity = alert.get("severity")
    alert = {**alert, "description": _clean_text(alert.get("description"))}
    return {
        "data_hora": alert.get("raisedAt"),
        "data_hora_iso": local_iso(alert.get("raisedAt")),
        "severidade": SOPHOS_SEVERITY.get(severity, severity),
        "tipo": alert.get("description") or humanize(alert.get("type") or ""),
        "descricao": alert.get("description"),
        "codigo": alert.get("type"),
        "categoria": alert.get("category"),
        "produto": SOPHOS_PRODUCT.get(alert.get("product"), alert.get("product")),
        "dispositivo": (alert.get("managedAgent") or {}).get("name"),
        "usuario": (alert.get("person") or {}).get("name"),
        "situacao": SOPHOS_ALERT_STATUS.get(alert.get("status"), alert.get("status")),
    }


def collect_sophos(api, platform: str, customer_name: str, period: Period | None = None,
                   environment: str = "") -> CollectionResult:
    """Endpoints (situação atual) e alertas gerados no período do tenant do cliente no Sophos Central."""
    period = period or last_days(7)
    result = CollectionResult(platform=platform, kind="sophos", environment=environment)
    try:
        tenant = api.customer_tenant(customer_name)
    except ApiError as exc:
        result.issues.append(_issue("cliente", exc))
        result.finished_at = now_iso()
        return result
    steps = (("dispositivos", lambda: api.endpoints(tenant), sophos_endpoint_row),
             ("alertas", lambda: api.alerts(tenant, period.since, period.until), sophos_alert_row))
    for name, fetch, to_row in steps:
        try:
            result.datasets[name] = [to_row(item) for item in fetch()]
        except ApiError as exc:
            result.issues.append(_issue(name, exc))
    result.summary = {"cliente_na_plataforma": tenant.get("name"), "periodo": period.label,
                      "regiao_dados": tenant.get("dataRegion"),
                      "observacao_alertas": "alertas gerados no período que a API do Sophos Central ainda lista"}
    result.finished_at = now_iso()
    return result


# --- Zabbix -------------------------------------------------------------------------

_ZABBIX_SEVERITY = {"5": "desastre", "4": "alta", "3": "media", "2": "atencao", "1": "informacao", "0": "nao_classificada"}


def _iso(epoch: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(epoch), timezone.utc).astimezone().isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError):
        return None


def zabbix_host_row(host: dict[str, Any]) -> dict[str, Any]:
    interfaces = host.get("interfaces") or []
    states = [str(i.get("available")) for i in interfaces]
    if not states:
        availability = "desconhecida"
    elif all(s == "1" for s in states):
        availability = "disponivel"
    elif all(s == "2" for s in states):
        availability = "indisponivel"
    elif "2" in states:
        availability = "parcial"
    else:
        availability = "desconhecida"
    monitored = str(host.get("status")) == "0"
    return {
        "nome": host.get("name") or host.get("host"),
        "host": host.get("host"),
        "monitorado": monitored,
        "status_monitoramento": "Monitorado" if monitored else "Não monitorado",
        "disponibilidade": availability,
        "interfaces_monitoradas": ", ".join(f"{i.get('ip') or i.get('dns')}:{i.get('port')}" for i in interfaces) or None,
    }


def zabbix_problem_row(problem: dict[str, Any], host_by_trigger: dict[str, str]) -> dict[str, Any]:
    resolved = str(problem.get("r_eventid") or "0") != "0"
    return {
        "host": host_by_trigger.get(str(problem.get("objectid"))),
        "descricao": problem.get("name"),
        "severidade": _ZABBIX_SEVERITY.get(str(problem.get("severity"))),
        "situacao": "resolvido" if resolved else "ativo",
        "status": "Resolvido" if resolved else "Ativo",
        "reconhecido": str(problem.get("acknowledged")) == "1",
        "data_hora_iso": _iso(problem.get("clock")),
    }


def collect_zabbix(api, platform: str, group_name: str, period: Period | None = None,
                   environment: str = "") -> CollectionResult:
    period = period or last_days(7)
    result = CollectionResult(platform=platform, kind="zabbix", environment=environment)
    try:
        groups = api.call("hostgroup.get", {"output": ["groupid", "name"], "filter": {"name": [group_name]}})
        if not groups:
            similar = api.call("hostgroup.get", {"output": ["name"], "search": {"name": group_name[:6]}, "limit": 10})
            raise ApiError(f"[zabbix] Grupo de hosts '{group_name}' não encontrado."
                           + (f" Parecidos: {', '.join(g['name'] for g in similar)}." if similar else "")
                           + " Ajuste com 'jervis customers link ... --external-name'.")
        group_ids = [g["groupid"] for g in groups]
        hosts = api.call("host.get", {"groupids": group_ids, "output": ["hostid", "host", "name", "status"],
                                      "selectInterfaces": ["ip", "dns", "port", "available"]})
        result.datasets["hosts"] = [zabbix_host_row(h) for h in hosts]
        problems = api.call("problem.get", {"groupids": group_ids, "output": "extend", "sortfield": ["eventid"],
                                            "sortorder": "DESC", "limit": 1000})
        trigger_ids = sorted({str(p["objectid"]) for p in problems})
        host_by_trigger = {}
        if trigger_ids:
            for trigger in api.call("trigger.get", {"triggerids": trigger_ids, "output": ["triggerid"],
                                                    "selectHosts": ["name"]}):
                names = [h["name"] for h in trigger.get("hosts") or []]
                host_by_trigger[str(trigger["triggerid"])] = ", ".join(names)
        result.datasets["problemas"] = [zabbix_problem_row(p, host_by_trigger) for p in problems]
        start, end = int(period.since.timestamp()), int(period.until.timestamp())
        result.datasets["disponibilidade"] = _zabbix_availability(api, group_ids, start, end)
        result.summary["alarmes_no_periodo"] = int(api.call("event.get", {
            "groupids": group_ids, "source": 0, "object": 0, "value": 1, "time_from": start, "time_till": end,
            "countOutput": True}))
        result.summary["periodo"] = period.label
    except ApiError as exc:
        result.issues.append(_issue("zabbix", exc))
    result.finished_at = now_iso()
    return result


def _zabbix_availability(api, group_ids: list[str], start: int, end: int) -> list[dict[str, Any]]:
    """Disponibilidade por host no período: média do item de ping (icmpping) nas tendências horárias."""
    items = api.call("item.get", {"groupids": group_ids, "output": ["itemid", "key_"], "selectHosts": ["name"],
                                  "filter": {"key_": ["icmpping"]}, "monitored": True})
    if not items:
        return []
    totals: dict[str, list[float]] = {}
    for trend in api.call("trend.get", {"itemids": [i["itemid"] for i in items], "time_from": start, "time_till": end,
                                        "output": ["itemid", "num", "value_avg"]}):
        acc = totals.setdefault(str(trend["itemid"]), [0.0, 0])
        acc[0] += float(trend["value_avg"]) * int(trend["num"])
        acc[1] += int(trend["num"])
    rows = []
    for item in items:
        weighted, samples = totals.get(str(item["itemid"]), (0.0, 0))
        if not samples:
            continue
        pct = round(100 * weighted / samples, 2)
        rows.append({"host": (item.get("hosts") or [{}])[0].get("name"), "indicador": "Disponibilidade (ping)",
                     "ok_pct": pct, "abaixo_da_meta": pct < 99.0, "amostras": samples})
    return rows


def _issue(stage: str, exc: ApiError) -> Issue:
    status = getattr(exc, "status", None)
    message = str(exc)
    if status in (401, 403) or "Not authorized" in message or "não autorizado" in message.lower():
        category = IssueCategory.AUTHENTICATION
    elif "não encontrado" in message:
        category = IssueCategory.CONFIGURATION
    else:
        category = IssueCategory.UNAVAILABLE
    return Issue(stage, category, message)

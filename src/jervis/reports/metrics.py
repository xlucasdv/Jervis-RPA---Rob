"""Indicadores de um cliente no período: base comum do relatório mensal, do executivo e do resumo em Markdown.

Também gera as recomendações priorizadas, a evolução frente ao período anterior e o acompanhamento das
recomendações anteriores (a partir do ``metricas.json`` da execução anterior do mesmo cliente).
Nada é estimado: indicador não coletado fica ausente (None) e os textos dizem "não coletado".
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

METRICS_FILE = "metricas.json"
MITRE_PT = {"Reconnaissance": "Reconhecimento", "Resource Development": "Desenvolvimento de recursos",
            "Initial Access": "Acesso inicial", "Execution": "Execução", "Persistence": "Persistência",
            "Privilege Escalation": "Escalonamento de privilégio", "Defense Evasion": "Evasão de defesas",
            "Credential Access": "Acesso a credenciais", "Discovery": "Descoberta", "Lateral Movement": "Movimento lateral",
            "Collection": "Coleta", "Command and Control": "Comando e controle", "Exfiltration": "Exfiltração",
            "Impact": "Impacto"}


def _alerts(records: list[dict[str, Any]], platform: str) -> list[dict[str, Any]]:
    return [r.get("detalhes") or {} for r in records
            if r["plataforma"] == platform and (r.get("origem") or "").startswith("alertas")]


def _days(text: str | None) -> int | None:
    match = re.search(r"há (\d+) dias", text or "")
    return int(match.group(1)) if match else None


def acronis_metrics(result: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    platform = result["platform"]
    ind = (result.get("summary") or {}).get("indicadores") or {}
    machines = (result.get("datasets") or {}).get("maquinas") or []
    activities = (result.get("datasets") or {}).get("atividades") or []
    alerts = _alerts(records, platform)
    by_type = Counter(a.get("tipo") for a in alerts)
    offline = sorted(((a.get("dispositivo"), _days(a.get("detalhe"))) for a in alerts
                      if a.get("tipo") in ("MachineOffline30", "MachineOffline20")), key=lambda x: -(x[1] or 0))
    disk = sorted({a.get("dispositivo") for a in alerts if a.get("tipo") == "MiMonitoringLowDiskSpace" and a.get("dispositivo")})
    service_down = [a.get("dispositivo") for a in alerts if a.get("tipo") == "ProtectionServiceNotWorking"]
    machine_records = [r for r in records if r["plataforma"] == platform and (r.get("origem") or "").startswith("maquinas")]
    vm = ind.get("maquinas_vulneraveis")
    tactics = ind.get("taticas")
    return {
        "inventario": ind.get("protecao") or {
            "gerenciados": len(machines), "protegidos": None, "desprotegidos": None, "descobertos": None},
        "maquinas_api": len(machines),
        "offline_agora": sum(1 for m in machines if m.get("online") is False),
        "backup": {"sem_plano": sum(1 for r in machine_records if "Sem plano de backup." in r.get("observacoes", [])),
                   "desatualizado": sum(1 for r in machine_records if "Backup desatualizado." in r.get("observacoes", [])),
                   "com_plano": sum(1 for m in machines if m.get("tem_backup"))},
        "ameacas": ind.get("ameacas"),
        "taticas": None if tactics is None else [
            {**t, "nome_pt": MITRE_PT.get(t["nome"], t["nome"])} for t in tactics if t["contagem"] or t["anterior"]],
        "incidentes_edr": ind.get("incidentes_edr"),
        "resumo_periodo": ind.get("resumo_periodo"),
        "maquinas_vulneraveis": None if vm is None else {
            "criticas": vm.get("critical", 0), "altas": vm.get("high", 0), "medias": vm.get("medium", 0),
            "baixas": vm.get("low", 0), "protegidas": vm.get("secured", 0) + vm.get("protected", 0), "sem_registro": vm.get("none", 0)},
        "vulnerabilidades": ind.get("vulnerabilidades"),
        "atualizacoes_faltantes": ind.get("atualizacoes_faltantes"),
        "patches": ind.get("patches"),
        "sessoes_remotas": ind.get("sessoes_remotas"),
        "alertas": {
            "total": len(alerts),
            "por_severidade": {s: sum(1 for a in alerts if a.get("severidade") == s)
                               for s in ("critical", "error", "warning", "information")},
            "offline": {"quantidade": len(offline), "exemplos": [{"maquina": m, "dias": d} for m, d in offline[:5]]},
            "pouco_espaco_disco": {"quantidade": len(disk), "maquinas": disk},
            "falhas_servico_protecao": {"ocorrencias": len(service_down), "maquinas": sorted(set(filter(None, service_down)))},
            "falhas_patch": by_type.get("PMInstallationFailed", 0),
            "reinicio_necessario": by_type.get("MiMonitoringWorkloadRequiresRestart", 0) + by_type.get("AcroinstRebootRequiredSuccessfulLocalInstall", 0),
            "falhas_coleta_monitor": by_type.get("MiMonitoringMetricGatheringFailed", 0),
            "perifericos_bloqueados": by_type.get("PeripheralDeviceAccessBlocked", 0),
            "por_tipo": [{"titulo": t, "quantidade": n} for t, n in Counter(a.get("titulo") for a in alerts).most_common(10)],
        },
        "atividades": {"total": len(activities),
                       "com_erro": sum(1 for a in activities if a.get("resultado") in ("error", "timedout", "abandoned"))},
        "fontes": ind.get("fontes") or {},
    }


def sophos_metrics(result: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    platform = result["platform"]
    data = result.get("datasets") or {}
    devices, alerts = data.get("dispositivos") or [], data.get("alertas") or []
    device_records = [r for r in records if r["plataforma"] == platform and (r.get("origem") or "").startswith("dispositivos")]
    stale = sorted(r["recurso"] for r in device_records if r["classificacao"] == "indisponivel" and r.get("recurso"))
    health = Counter(d.get("saude") or "unknown" for d in devices)

    def names(rows):
        found = sorted({d.get("nome") for d in rows if d.get("nome")})
        return {"quantidade": len(rows), "maquinas": found}

    high = [a for a in alerts if a.get("severidade") == "alta"]
    return {
        "endpoints": {"total": len(devices), "computadores": sum(1 for d in devices if d.get("tipo") == "Computador"),
                      "servidores": sum(1 for d in devices if d.get("tipo") == "Servidor")},
        "saude": {"boa": health["good"], "suspeita": health["suspicious"], "ruim": health["bad"], "desconhecida": health["unknown"]},
        "ameacas_ativas": names([d for d in devices if d.get("saude_ameacas") in ("bad", "suspicious")]),
        "servicos_com_falha": names([d for d in devices if d.get("saude_servicos") in ("bad", "suspicious")]),
        "adulteracao_desativada": names([d for d in devices if d.get("protecao_adulteracao") is False]),
        "isolados": sum(1 for d in devices if d.get("isolado")),
        "sem_comunicacao": {"quantidade": len(stale), "maquinas": stale},
        "alertas": {
            "total": len(alerts),
            "por_severidade": {s: sum(1 for a in alerts if a.get("severidade") == s) for s in ("alta", "media", "baixa")},
            "por_categoria": [{"categoria": c, "quantidade": q} for c, q in Counter(a.get("categoria") or "outros" for a in alerts).most_common(8)],
            "por_tipo": [{"titulo": t, "quantidade": q} for t, q in Counter(a.get("tipo") for a in alerts).most_common(10)],
            "maquinas_alta": sorted({a.get("dispositivo") for a in high if a.get("dispositivo")}),
        },
    }


def zabbix_metrics(result: dict[str, Any]) -> dict[str, Any]:
    data = result.get("datasets") or {}
    hosts, problems, availability = data.get("hosts") or [], data.get("problemas") or [], data.get("disponibilidade") or []
    pcts = [a["ok_pct"] for a in availability if isinstance(a.get("ok_pct"), (int, float))]
    active = [p for p in problems if p.get("situacao") != "resolvido"]
    return {
        "disponibilidade_geral": round(sum(pcts) / len(pcts), 2) if pcts else None,
        "abaixo_95": [{"host": a["host"], "pct": a["ok_pct"]} for a in sorted(availability, key=lambda a: a["ok_pct"]) if a["ok_pct"] < 95],
        "hosts": len(hosts), "indisponiveis": sum(1 for h in hosts if h.get("disponibilidade") == "indisponivel"),
        "desativados": sum(1 for h in hosts if h.get("monitorado") is False),
        "alarmes_no_periodo": (result.get("summary") or {}).get("alarmes_no_periodo"),
        "problemas_ativos": len(active),
        "problemas_graves": sum(1 for p in active if p.get("severidade") in ("desastre", "alta")),
        "problemas_por_descricao": [{"descricao": d, "quantidade": n} for d, n in Counter(p.get("descricao") for p in active).most_common(5)],
    }


def compute(results: list[dict[str, Any]], consolidated: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    records = consolidated["registros"]
    metrics: dict[str, Any] = {
        "cliente": meta.get("cliente"), "periodo": meta.get("periodo"), "periodo_curto": meta.get("periodo_curto"),
        "competencia": meta.get("competencia"), "gerado_em": consolidated.get("gerado_em"),
        "parcial": bool(meta.get("parcial")),
        "contrato": meta.get("contrato") or {}, "plataformas": {}, "avisos": [],
    }
    for result in results:
        kind = result.get("kind")
        if result.get("status") == "falha":
            metrics["avisos"].append(f"{result['platform']}: coleta não concluída")
            continue
        if kind == "acronis":
            metrics["plataformas"][result["platform"]] = {"tipo": "acronis", **acronis_metrics(result, records)}
        elif kind == "sophos":
            metrics["plataformas"][result["platform"]] = {"tipo": "sophos", **sophos_metrics(result, records)}
        elif kind == "zabbix":
            metrics["plataformas"][result["platform"]] = {"tipo": "zabbix", **zabbix_metrics(result)}
        for issue in result.get("issues") or []:
            if issue.get("severity") == "aviso":
                metrics["avisos"].append(issue.get("message"))
    metrics["recomendacoes"] = recommendations(metrics)
    return metrics


def first(metrics: dict[str, Any], kind: str) -> dict[str, Any] | None:
    return next((m for m in metrics.get("plataformas", {}).values() if m.get("tipo") == kind), None)


def _n(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def recommendations(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Recomendações priorizadas (alta, média, baixa). ``chave`` identifica o tema entre os meses (follow-up)."""
    recs: list[dict[str, Any]] = []

    def add(key, crit, point, action):
        recs.append({"chave": key, "criticidade": crit, "ponto": point, "acao": action})

    a = first(metrics, "acronis")
    if a:
        vuln, vm = a.get("vulnerabilidades"), a.get("maquinas_vulneraveis")
        if vuln and (vuln["por_severidade"].get("critical", 0) + vuln["por_severidade"].get("high", 0)):
            high = vuln["por_severidade"].get("critical", 0) + vuln["por_severidade"].get("high", 0)
            products = ", ".join(p["produto"] for p in vuln.get("produtos_criticos", [])[:5])
            add("vulnerabilidades", "alta",
                f"{_n(high)} vulnerabilidades Altas/Críticas" + (f"; {vm['criticas']} máquinas em nível Crítico" if vm else "") + ".",
                f"Priorizar a atualização de {products or 'softwares vulneráveis'}"
                + (f", começando pelas {vm['criticas']} máquinas críticas." if vm and vm["criticas"] else "."))
        patches = a.get("patches")
        if patches and patches.get("maquinas_com_falha"):
            tried = patches["maquinas_com_falha"] + patches["maquinas_instaladas"]
            add("patches", "alta", f"Falha na instalação de patches em {patches['maquinas_com_falha']} de {tried} máquina(s) no período.",
                "Investigar a causa raiz das falhas (espaço em disco, reinicializações pendentes) e reexecutar a instalação.")
        inv = a.get("inventario") or {}
        if inv.get("desprotegidos") or inv.get("descobertos"):
            add("desprotegidos", "alta",
                f"{inv.get('desprotegidos', 0)} endpoint(s) desprotegido(s)" + (f" e {inv['descobertos']} dispositivo(s) descoberto(s) sem agente" if inv.get("descobertos") else "") + ".",
                "Validar e reativar a proteção nos endpoints desprotegidos e instalar o agente nos dispositivos descobertos.")
        backup = a.get("backup") or {}
        if backup.get("desatualizado"):
            add("backup_desatualizado", "alta", f"{backup['desatualizado']} máquina(s) com backup desatualizado ou nunca concluído.",
                "Verificar por que os backups pararam (agente, destino, credenciais) e executar um backup completo.")
        if backup.get("sem_plano") and backup.get("com_plano"):
            add("backup_sem_plano", "alta", f"{backup['sem_plano']} máquina(s) sem plano de backup.", "Aplicar plano de backup e validar a execução.")
        alerts = a.get("alertas") or {}
        down = alerts.get("falhas_servico_protecao") or {}
        if down.get("ocorrencias"):
            add("servico_protecao", "media", f"{down['ocorrencias']} falha(s) do serviço de proteção ({', '.join(down['maquinas'])}).",
                "Verificar a estabilidade do agente nesses dispositivos; reinstalar/atualizar se houver recorrência.")
        off = alerts.get("offline") or {}
        if off.get("quantidade"):
            longest = max((e["dias"] or 0 for e in off["exemplos"]), default=0)
            add("offline", "media", f"{off['quantidade']} máquina(s) offline há mais de 20/30 dias" + (f" (até {longest} dias)." if longest else "."),
                "Auditar os ativos com o cliente: reconectar os que estão em uso e remover/revogar a licença dos demais.")
        disk = alerts.get("pouco_espaco_disco") or {}
        if disk.get("quantidade"):
            add("disco", "media", f"{disk['quantidade']} dispositivo(s) com pouco espaço livre em disco.",
                "Liberar espaço nos dispositivos afetados para não bloquear atualizações e backups.")
        tactics = [t for t in (a.get("taticas") or []) if t["contagem"]]
        if tactics:
            text = "; ".join(f"{t['nome_pt']}: {t['contagem']}" for t in tactics)
            add("taticas", "media", f"Detecções por tática MITRE ATT&CK no período ({text}).",
                "Revisar os dispositivos envolvidos no console de EDR e orientar os respectivos usuários.")
        summary = a.get("resumo_periodo") or {}
        if summary.get("urls_maliciosas_bloqueadas"):
            add("urls", "baixa", f"{_n(summary['urls_maliciosas_bloqueadas'])} bloqueio(s) de URLs maliciosas no período.",
                "Reforçar a conscientização dos usuários sobre phishing e links maliciosos.")
        if summary.get("perifericos_bloqueados"):
            add("perifericos", "baixa", f"{summary['perifericos_bloqueados']} tentativa(s) de uso de periféricos bloqueada(s).",
                "Revisar com o cliente se a política de periféricos está adequada às necessidades das áreas.")
    s = first(metrics, "sophos")
    if s:
        def few(items):
            return ", ".join(items[:5]) + (" e outros" if len(items) > 5 else "")
        threats, services = s["ameacas_ativas"], s["servicos_com_falha"]
        if threats["quantidade"]:
            add("sophos_ameacas", "alta", f"{threats['quantidade']} endpoint(s) com ameaça ativa no Sophos Central ({few(threats['maquinas'])}).",
                "Investigar e limpar as ameaças no Sophos Central e confirmar a remediação em cada endpoint.")
        if services["quantidade"]:
            add("sophos_servicos", "alta", f"{services['quantidade']} endpoint(s) com serviços de proteção do Sophos parados ou com falha "
                f"({few(services['maquinas'])}).",
                "Reiniciar ou reinstalar o agente Sophos nesses endpoints e confirmar que os serviços voltaram a ficar íntegros.")
        high = s["alertas"]["por_severidade"]["alta"]
        if high:
            machines = s["alertas"]["maquinas_alta"]
            add("sophos_alertas_altos", "alta", f"{high} alerta(s) de severidade alta no Sophos Central no período"
                + (f" ({few(machines)})." if machines else "."),
                "Tratar os alertas de severidade alta e confirmar a resolução no console do Sophos Central.")
        tamper = s["adulteracao_desativada"]
        if tamper["quantidade"]:
            add("sophos_adulteracao", "media", f"{tamper['quantidade']} endpoint(s) com a proteção contra adulteração desativada "
                f"({few(tamper['maquinas'])}).",
                "Reativar a proteção contra adulteração (Tamper Protection) para impedir que o agente seja desligado ou removido.")
        stale = s["sem_comunicacao"]
        if stale["quantidade"]:
            add("sophos_sem_comunicacao", "media", f"{stale['quantidade']} endpoint(s) sem comunicação recente com o Sophos Central "
                f"({few(stale['maquinas'])}).",
                "Verificar com o cliente se os equipamentos seguem em uso: reconectar os ativos e remover do console os desativados.")
    z = first(metrics, "zabbix")
    if z:
        if z["abaixo_95"]:
            add("disponibilidade", "media", f"{len(z['abaixo_95'])} ativo(s) com disponibilidade abaixo de 95%: "
                + ", ".join(x["host"] for x in z["abaixo_95"][:5]) + ".",
                "Investigar quedas de conectividade (link, energia, equipamento) nesses ativos.")
        if z["indisponiveis"]:
            add("indisponiveis", "alta", f"{z['indisponiveis']} ativo(s) indisponível(is) no monitoramento.", "Verificar e restabelecer a comunicação.")
        if isinstance(z.get("alarmes_no_periodo"), int) and z["hosts"] and z["alarmes_no_periodo"] > 20 * z["hosts"]:
            add("alarmes", "baixa", f"Volume elevado de alarmes ({_n(z['alarmes_no_periodo'])} no período).",
                "Revisar thresholds para reduzir ruído operacional sem perder eventos relevantes.")
    order = {"alta": 0, "media": 1, "baixa": 2}
    return sorted(recs, key=lambda r: order[r["criticidade"]])


# --- histórico ----------------------------------------------------------------------------


def previous(run_dir: Path) -> dict[str, Any] | None:
    """metricas.json da execução anterior do mesmo cliente com competência (mês) diferente, se houver."""
    current = None
    try:
        current = json.loads((run_dir / METRICS_FILE).read_text(encoding="utf-8")).get("competencia")
    except (OSError, ValueError):
        pass
    for folder in sorted((p for p in run_dir.parent.iterdir() if p.is_dir() and p.name < run_dir.name), reverse=True):
        try:
            data = json.loads((folder / METRICS_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if current is None or (data.get("competencia") and data["competencia"] < current):
            return data
    return None


def evolution(current: dict[str, Any], before: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Indicadores comparáveis entre os dois períodos, com a leitura (melhora/piora/estável)."""
    if not before:
        return []
    rows = []

    partial = bool(current.get("parcial")) or bool(before.get("parcial"))

    def compare(label, path, lower_is_better=True, flow=False):
        # flow: total acumulado no período; com um dos períodos incompleto, a comparação seria injusta
        if flow and partial:
            return

        def get(m):
            value = m
            for key in path:
                value = value.get(key) if isinstance(value, dict) else None
            return value
        old, new = get(before), get(current)
        if not isinstance(old, (int, float)) or not isinstance(new, (int, float)):
            return
        if new == old or (old and abs(new - old) / old < 0.03):
            reading = "estável"
        elif (new < old) == lower_is_better:
            reading = "melhora"
        else:
            reading = "piora"
        rows.append({"indicador": label, "anterior": old, "atual": new, "leitura": reading})

    for platform, m in current.get("plataformas", {}).items():
        base = ("plataformas", platform)
        if m.get("tipo") == "acronis":
            compare("Ameaças não mitigadas", base + ("ameacas", "nao_mitigadas"))
            compare("Endpoints desprotegidos", base + ("inventario", "desprotegidos"))
            compare("Dispositivos gerenciados", base + ("inventario", "gerenciados"), lower_is_better=False)
            compare("Máquinas offline", base + ("offline_agora",))
            compare("Máquinas em nível Crítico de vulnerabilidade", base + ("maquinas_vulneraveis", "criticas"))
            compare("Vulnerabilidades Críticas", base + ("vulnerabilidades", "por_severidade", "critical"))
            compare("Vulnerabilidades Altas", base + ("vulnerabilidades", "por_severidade", "high"))
            compare("Atualizações de segurança faltantes", base + ("atualizacoes_faltantes", "seguranca"))
            compare("Incidentes EDR", base + ("incidentes_edr", "total"), flow=True)
            compare("Mitigações manuais (incidentes)", base + ("incidentes_edr", "manuais"), flow=True)
            compare("Máquinas com falha de patch", base + ("patches", "maquinas_com_falha"), flow=True)
            compare("URLs maliciosas bloqueadas", base + ("resumo_periodo", "urls_maliciosas_bloqueadas"), flow=True)
        elif m.get("tipo") == "sophos":
            compare("Endpoints Sophos gerenciados", base + ("endpoints", "total"), lower_is_better=False)
            compare("Endpoints Sophos com ameaça ativa", base + ("ameacas_ativas", "quantidade"))
            compare("Endpoints Sophos com serviços com falha", base + ("servicos_com_falha", "quantidade"))
            compare("Endpoints Sophos sem proteção contra adulteração", base + ("adulteracao_desativada", "quantidade"))
            compare("Endpoints Sophos sem comunicação", base + ("sem_comunicacao", "quantidade"))
            compare("Alertas Sophos de severidade alta", base + ("alertas", "por_severidade", "alta"), flow=True)
        elif m.get("tipo") == "zabbix":
            compare("Disponibilidade geral (%)", base + ("disponibilidade_geral",), lower_is_better=False, flow=True)
            compare("Problemas ativos", base + ("problemas_ativos",))
            compare("Alarmes disparados", base + ("alarmes_no_periodo",), flow=True)
    return rows


def follow_up(current: dict[str, Any], before: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Recomendações do período anterior: pendente se o tema continua aparecendo, resolvida se não."""
    if not before:
        return []
    now = {r["chave"]: r for r in current.get("recomendacoes", [])}
    rows = []
    for r in before.get("recomendacoes", []):
        if r["criticidade"] == "baixa" or r["chave"] in INFORMATIONAL:
            continue  # só o que exige ação entra no acompanhamento
        if r["chave"] not in now:
            status, note = "Resolvida", "Tema não aparece mais neste período."
        elif now[r["chave"]]["ponto"] == r["ponto"]:
            status, note = "Pendente", f"Sem alteração. Ação: {r['acao']}"
        else:
            status, note = "Pendente", f"Situação atual: {now[r['chave']]['ponto']}"
        rows.append({"recomendacao": r["ponto"], "status": status, "observacao": note})
    return rows


# Temas informativos (volume de bloqueios, detecções, alarmes): fazem parte do relatório, não do acompanhamento.
INFORMATIONAL = frozenset({"urls", "perifericos", "taticas", "alarmes"})


def save(metrics: dict[str, Any], run_dir: Path) -> Path:
    path = run_dir / METRICS_FILE
    path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path

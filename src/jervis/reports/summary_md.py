"""Resumo em Markdown do período (MSR): base de leitura rápida e insumo para a IA escrever o relatório executivo."""

from __future__ import annotations

from typing import Any

from jervis.reports.metrics import first

NC = "não coletado"
SEVERITY_PT = {"critical": "Críticos", "error": "Erros", "warning": "Avisos", "information": "Informações"}

AI_INSTRUCTIONS = """Com base nas informações acima, gere um relatório executivo mensal de segurança para o cliente {cliente}.

O relatório deve:
- Ter linguagem executiva, clara e profissional
- Destacar os principais pontos de atenção com contexto de risco
- Apresentar as recomendações com criticidade (Alta / Média / Baixa) e ação sugerida
- Incluir uma seção de evolução comparando com o mês anterior quando os dados permitirem
- Não inventar dados — usar apenas o que foi informado acima; indicadores marcados como "não coletado" não devem ser citados como números
- Não usar jargão técnico sem explicação quando o público for executivo"""


def n(value: Any) -> str:
    if value is None:
        return NC
    if isinstance(value, float):
        return f"{value:.2f}".replace(".", ",")
    return f"{value:,}".replace(",", ".") if isinstance(value, int) else str(value)


def _machines(group: dict[str, Any], limit: int = 12) -> str:
    names = group.get("maquinas") or []
    return f" ({', '.join(names[:limit])}{' e outras' if len(names) > limit else ''})" if names else ""


def sophos_section(s: dict[str, Any]) -> list[str]:
    ep, health, alerts = s["endpoints"], s["saude"], s["alertas"]
    sev = alerts["por_severidade"]
    out = ["## Sophos Central", "", "### Métricas do período"]
    if ep["total"]:
        out += [f"- Endpoints gerenciados: {n(ep['total'])} ({n(ep['computadores'])} computadores | {n(ep['servidores'])} servidores)",
                f"- Saúde dos endpoints: {n(health['boa'])} boa | {n(health['suspeita'])} suspeita | {n(health['ruim'])} ruim | "
                f"{n(health['desconhecida'])} desconhecida",
                f"- Endpoints com ameaça ativa: {n(s['ameacas_ativas']['quantidade'])}{_machines(s['ameacas_ativas'])}",
                f"- Endpoints com item suspeito pendente (ex.: PUA): {n((s.get('itens_suspeitos') or {}).get('quantidade'))}"
                f"{_machines(s.get('itens_suspeitos') or {})}",
                f"- Endpoints com serviços de proteção com falha: {n(s['servicos_com_falha']['quantidade'])}{_machines(s['servicos_com_falha'])}",
                f"- Proteção contra adulteração desativada: {n(s['adulteracao_desativada']['quantidade'])}{_machines(s['adulteracao_desativada'])}",
                f"- Endpoints offline no momento da coleta: {n(s.get('offline_agora'))}",
                f"- Endpoints isolados: {n(s['isolados'])}",
                f"- Endpoints sem comunicação recente: {n(s['sem_comunicacao']['quantidade'])}{_machines(s['sem_comunicacao'])}"]
        if (s.get("nomes_repetidos") or {}).get("quantidade"):
            out.append(f"- Nomes com mais de um registro no console: {n(s['nomes_repetidos']['quantidade'])}{_machines(s['nomes_repetidos'])}")
    else:
        out.append("- Endpoints gerenciados: 0 (nenhum computador ou servidor deste cliente no Sophos Central)")
    out.append(f"- Alertas gerados no período: {n(alerts['total'])} ({n(sev['alta'])} alta | {n(sev['media'])} média | {n(sev['baixa'])} baixa)")
    if alerts.get("por_produto"):
        out.append("- Alertas por origem: " + "; ".join(f"{p}: {q}" for p, q in alerts["por_produto"].items()))
    if alerts["por_categoria"]:
        out.append("- Alertas por categoria: " + "; ".join(f"{c['categoria']}: {c['quantidade']}" for c in alerts["por_categoria"]))
    if alerts["por_tipo"]:
        out.append("- Principais alertas: " + "; ".join(f"{t['titulo']} ({t['quantidade']})" for t in alerts["por_tipo"][:5]))
    out += ["", "### Anomalias e pontos de atenção"]
    anomalies = []
    if s["ameacas_ativas"]["quantidade"]:
        anomalies.append(f"**Ameaças Ativas:** {s['ameacas_ativas']['quantidade']} endpoint(s) com ameaça ainda não limpa.")
    if (s.get("itens_suspeitos") or {}).get("quantidade"):
        anomalies.append(f"**Itens Suspeitos Pendentes:** {s['itens_suspeitos']['quantidade']} endpoint(s){_machines(s['itens_suspeitos'], 8)}.")
    if s["servicos_com_falha"]["quantidade"]:
        anomalies.append(f"**Serviços de Proteção com Falha:** {s['servicos_com_falha']['quantidade']} endpoint(s).")
    if sev["alta"]:
        anomalies.append(f"**Alertas de Severidade Alta:** {sev['alta']} no período" + _machines({"maquinas": alerts["maquinas_alta"]}, 8) + ".")
    if s["adulteracao_desativada"]["quantidade"]:
        anomalies.append(f"**Proteção contra Adulteração Desativada:** {s['adulteracao_desativada']['quantidade']} endpoint(s).")
    if s["sem_comunicacao"]["quantidade"]:
        anomalies.append(f"**Endpoints sem Comunicação:** {s['sem_comunicacao']['quantidade']} registro(s) sem contato recente com o console.")
    out += [f"- {x}" for x in anomalies] or ["- Nenhuma anomalia relevante no período."]
    return out + ["", "---", ""]


def render(metrics: dict[str, Any], evolution: list[dict[str, Any]], follow: list[dict[str, Any]]) -> str:
    client, period = metrics.get("cliente") or "Cliente", metrics.get("periodo_curto") or metrics.get("periodo") or ""
    out = [f"# Resumo MSR – {client} – {period}", ""]
    a, s, z = first(metrics, "acronis"), first(metrics, "sophos"), first(metrics, "zabbix")

    # contexto
    out += ["## Contexto do Ambiente"]
    products = []
    for contract in (metrics.get("contrato") or {}).values():
        devices = contract.get("dispositivos")
        products += [f"{p}" + (f" ({devices} dispositivos contratados)" if devices else "") for p in contract.get("produtos") or []]
    out.append(f"- Produtos monitorados: {' e '.join(products) if products else NC}")
    context = []
    if a:
        inv = a["inventario"]
        context.append(f"O ambiente possui {n(inv.get('gerenciados'))} dispositivos gerenciados no console Acronis, dos quais "
                       f"{n(inv.get('protegidos'))} estão com proteção ativa e {n(inv.get('desprotegidos'))} encontram-se desprotegidos.")
        sessions = a.get("sessoes_remotas")
        if sessions:
            context.append(f"No período, foram contabilizadas {n(sessions['total'])} sessões remotas de suporte.")
    if s:
        ep = s["endpoints"]
        if ep["total"]:
            context.append(f"O Sophos Central protege {n(ep['total'])} endpoints ({n(ep['computadores'])} computadores e "
                           f"{n(ep['servidores'])} servidores).")
        else:
            origins = ", ".join(f"{p} ({q})" for p, q in (s["alertas"].get("por_produto") or {}).items())
            context.append("O Sophos Central não tem endpoints deste cliente" + (f"; os alertas do período vêm de: {origins}." if origins else "."))
    if z:
        context.append(f"O monitoramento (Zabbix) cobre {n(z['hosts'])} ativos, com disponibilidade geral de "
                       f"{n(z['disponibilidade_geral'])}% no período.")
    out += [f"- Observações gerais: {' '.join(context) if context else NC}", "", "---", ""]

    if a:
        inv, threats, inc, summary = a["inventario"], a.get("ameacas"), a.get("incidentes_edr"), a.get("resumo_periodo") or {}
        tactics = a.get("taticas")
        alerts = a["alertas"]
        out += ["## Endpoint Security & EDR (Acronis)", "", "### Métricas do período",
                f"- Dispositivos Gerenciados: {n(inv.get('gerenciados'))} | Protegidos: {n(inv.get('protegidos'))} | "
                f"Desprotegidos: {n(inv.get('desprotegidos'))} | Descobertos: {n(inv.get('descobertos'))}"]
        if threats:
            out.append(f"- Ameaças mitigadas (situação atual do painel): {n(threats['total'])} ({n(threats['automaticas'])} mitigações "
                       f"automáticas | {n(threats['manuais'])} manuais | {n(threats['nao_mitigadas'])} não mitigadas)")
        else:
            out.append(f"- Ameaças mitigadas: {NC}")
        out.append(f"- Ameaças mitigadas no período (resumo de proteção): {n(summary.get('ameacas_mitigadas'))}")
        if inc:
            out.append(f"- Incidentes EDR no período: {n(inc['total'])} ({n(inc['automaticos'])} mitigados automaticamente | "
                       f"{n(inc['manuais'])} manualmente | {n(inc['nao_mitigados'])} não mitigados | {n(inc['em_investigacao'])} em investigação)")
            if inc.get("maquinas"):
                out.append(f"- Dispositivos com incidentes EDR: {len(inc['maquinas'])} máquinas ({', '.join(inc['maquinas'][:12])}"
                           + (" e outras" if len(inc["maquinas"]) > 12 else "") + ")")
        if tactics is None:
            out.append(f"- Detecções por tática (MITRE ATT&CK): {NC}")
        elif tactics:
            out.append("- Detecções por tática (MITRE ATT&CK): " + "; ".join(
                f"**{t['nome_pt']}**: {t['contagem']} (período anterior: {t['anterior']})" for t in tactics) + "; 0 nas demais táticas.")
        else:
            out.append("- Detecções por tática (MITRE ATT&CK): nenhuma no período.")
        out.append(f"- Proteção Web: {n(summary.get('urls_maliciosas_bloqueadas'))} bloqueios de acesso a URLs maliciosas")
        out.append(f"- Controle de Periféricos: {n(summary.get('perifericos_bloqueados'))} tentativas de acesso a dispositivos periféricos bloqueadas")
        down = alerts["falhas_servico_protecao"]
        out += ["", "### Anomalias e pontos de atenção"]
        anomalies = []
        if inv.get("desprotegidos"):
            anomalies.append(f"**Endpoints Desprotegidos:** {inv['desprotegidos']} máquinas gerenciadas sem proteção ativa operacional.")
        if inc and inc["total"]:
            anomalies.append(f"**Incidentes EDR:** {inc['total']} incidentes no período em {len(inc.get('maquinas', []))} dispositivos.")
        if down["ocorrencias"]:
            anomalies.append(f"**Falhas no Serviço de Proteção:** {down['ocorrencias']} ocorrência(s) (máquinas {', '.join(down['maquinas'])}).")
        if summary.get("urls_maliciosas_bloqueadas"):
            anomalies.append(f"**Tentativas de Acesso a Web Maliciosa:** {n(summary['urls_maliciosas_bloqueadas'])} bloqueios de URLs nocivas.")
        backup = a["backup"]
        if backup["sem_plano"] or backup["desatualizado"]:
            anomalies.append(f"**Backup:** {backup['sem_plano']} máquinas sem plano de backup e {backup['desatualizado']} com backup desatualizado.")
        out += [f"- {x}" for x in anomalies] or ["- Nenhuma anomalia relevante no período."]
        out += ["", "---", "", "## Gestão de Vulnerabilidades e Patches (Acronis)", "", "### Métricas do período"]
        vm, vuln, missing, patches = a.get("maquinas_vulneraveis"), a.get("vulnerabilidades"), a.get("atualizacoes_faltantes"), a.get("patches")
        if vm:
            out += ["- Perfil de vulnerabilidade dos dispositivos:",
                    f"  - Nível Crítico: {n(vm['criticas'])} máquinas", f"  - Nível Alto: {n(vm['altas'])} máquinas",
                    f"  - Nível Médio / Baixo: {n(vm['medias'] + vm['baixas'])} máquinas ({vm['medias']} Média, {vm['baixas']} Baixa)",
                    f"  - Protegidos / Sem vulnerabilidades detectadas: {n(vm['protegidas'] + vm['sem_registro'])} máquinas "
                    f"({vm['protegidas']} Protegidas, {vm['sem_registro']} Nenhum)"]
        else:
            out.append(f"- Perfil de vulnerabilidade dos dispositivos: {NC}")
        if vuln:
            sev = vuln["por_severidade"]
            out += [f"- Volume total de vulnerabilidades identificadas: {n(vuln['total'])} vulnerabilidades",
                    f"  - Críticas: {n(sev.get('critical', 0))}", f"  - Altas: {n(sev.get('high', 0))}", f"  - Médias: {n(sev.get('medium', 0))}",
                    f"  - Baixas / Não classificadas: {n(sev.get('low', 0) + sev.get('none', 0))} ({n(sev.get('low', 0))} Baixas, {n(sev.get('none', 0))} Nenhum)"]
            if vuln.get("produtos_criticos"):
                out.append("- Softwares mais afetados por vulnerabilidades críticas: " + "; ".join(
                    f"{p['produto']} ({p['criticas']} críticas em {p['maquinas']} máquinas; ex.: {', '.join(p['cves'])})"
                    for p in vuln["produtos_criticos"][:5]))
        else:
            out.append(f"- Volume total de vulnerabilidades identificadas: {NC}")
        out.append("- Gestão e Aplicação de Patches:")
        out.append("  - Atualizações faltantes catalogadas: " + (f"{n(missing['seguranca'])} de Segurança, {n(missing['criticas'])} Críticas e "
                                                                  f"{n(missing['outras'])} de outras categorias." if missing else NC))
        out.append("  - Resultado das instalações de patches: " + (
            f"{n(patches['maquinas_instaladas'])} máquinas com instalação concluída | {n(patches['maquinas_com_falha'])} com falha | "
            f"{n(patches['maquinas_reinicio_pendente'])} pendentes de reinicialização ({n(patches['atualizacoes_instaladas'])} atualizações "
            f"instaladas, {n(patches['atualizacoes_com_falha'])} com falha)" if patches else NC))
        sev = alerts["por_severidade"]
        out.append(f"- Alertas da Console no período: {n(alerts['total'])} alertas no total")
        out.append(f"  - Críticos: {sev['critical']}" + (" (máquinas offline há mais de 30 dias; ex.: " + ", ".join(
            f"{e['maquina']} há {e['dias']} dias" for e in alerts["offline"]["exemplos"][:3] if e["dias"]) + ")" if alerts["offline"]["quantidade"] else ""))
        out.append(f"  - Erros: {sev['error']} ({alerts['falhas_coleta_monitor']} falhas na coleta de dados/monitores, "
                   f"{down['ocorrencias']} serviços de proteção sem resposta)")
        out.append(f"  - Avisos: {sev['warning']} ({alerts['falhas_patch']} falhas de patching, {alerts['pouco_espaco_disco']['quantidade']} "
                   f"alertas de pouco espaço livre em disco, {alerts['reinicio_necessario']} solicitações de reinicialização)")
        out.append(f"  - Informações: {sev['information']}")
        sessions = a.get("sessoes_remotas")
        out.append("- Sessões de Acesso Remoto: " + (f"{n(sessions['total'])} acessos efetuados (" + ", ".join(
            f"{c} realizados por {u}" for u, c in sessions["por_usuario"].items()) + ")." if sessions else NC))
        out += ["", "### Anomalias e pontos de atenção"]
        anomalies = []
        if vuln:
            high = vuln["por_severidade"].get("critical", 0) + vuln["por_severidade"].get("high", 0)
            anomalies.append(f"**Volume de Vulnerabilidades Ativas:** {n(vuln['total'])} vulnerabilidades no parque, das quais "
                             f"{n(high)} são de criticidade Alta ou Crítica.")
        if patches and patches["maquinas_com_falha"]:
            anomalies.append(f"**Insucesso na Aplicação de Patches:** falha em {patches['maquinas_com_falha']} de "
                             f"{patches['maquinas_com_falha'] + patches['maquinas_instaladas']} máquinas com instalação no período.")
        if alerts["offline"]["quantidade"]:
            anomalies.append(f"**Máquinas Inativas/Offline:** {alerts['offline']['quantidade']} endpoints há mais de 20/30 dias sem conectar à console.")
        if alerts["pouco_espaco_disco"]["quantidade"]:
            anomalies.append(f"**Alertas de Espaço em Disco:** {alerts['pouco_espaco_disco']['quantidade']} dispositivos com pouco espaço livre.")
        out += [f"- {x}" for x in anomalies] or ["- Nenhuma anomalia relevante no período."]
        out += ["", "---", ""]

    if s:
        out += sophos_section(s)

    if z:
        out += ["## Monitoramento de Infraestrutura (Zabbix)", "", "### Métricas do período",
                f"- Disponibilidade geral: {n(z['disponibilidade_geral'])}%",
                f"- Ativos monitorados: {n(z['hosts'])} ({n(z['indisponiveis'])} indisponíveis, {n(z['desativados'])} desativados)",
                f"- Alarmes disparados: {n(z['alarmes_no_periodo'])}",
                f"- Problemas ativos: {n(z['problemas_ativos'])} ({n(z['problemas_graves'])} de severidade alta ou desastre)"]
        if z["abaixo_95"]:
            out.append("- Ativos abaixo de 95% de disponibilidade: " + ", ".join(f"{x['host']} ({n(x['pct'])}%)" for x in z["abaixo_95"]))
        out += ["", "---", ""]

    if evolution:
        out += ["## Evolução em relação ao período anterior", ""]
        if metrics.get("parcial"):
            out += ["Mês em andamento: comparados só os indicadores de situação (totais acumulados do mês ficam para o fechamento).", ""]
        out += ["| Indicador | Anterior | Atual | Leitura |", "|---|---|---|---|"]
        out += [f"| {e['indicador']} | {n(e['anterior'])} | {n(e['atual'])} | {e['leitura']} |" for e in evolution]
        out += ["", "---", ""]
    out += ["## Follow-up de Recomendações Anteriores", ""]
    if follow:
        out += ["| Recomendação | Status | Observação |", "|---|---|---|"]
        out += [f"| {f['recomendacao']} | {f['status']} | {f['observacao']} |" for f in follow]
    else:
        out.append("Sem relatório anterior deste cliente para acompanhamento.")
    out += ["", "## Recomendações do Período", "", "| Criticidade | Ponto de atenção | Ação recomendada |", "|---|---|---|"]
    out += [f"| {r['criticidade'].capitalize().replace('Media', 'Média')} | {r['ponto']} | {r['acao']} |" for r in metrics.get("recomendacoes", [])]
    if metrics.get("avisos"):
        out += ["", "## Limitações da coleta", ""] + [f"- {w}" for w in metrics["avisos"]]
    out += ["", "---", "", "## Insumo para a IA", "", AI_INSTRUCTIONS.format(cliente=client), ""]
    return "\n".join(out)

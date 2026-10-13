"""Relatório Executivo Mensal (documento A4): sumário, painel de indicadores, pontos de atenção com contexto de
risco, recomendações, evolução, acompanhamento e considerações finais.

Os textos são escritos por modelos preenchidos com os indicadores (``narrative``); opcionalmente substituídos
pelo texto da IA (``jervis.reports.ai``), que só é aceito se não trouxer números ausentes dos dados.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from jervis.reports.metrics import first

MONTHS = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro",
          "novembro", "dezembro"]
CRIT_LABEL = {"alta": "Alta", "media": "Média", "baixa": "Baixa"}


def n(value: Any) -> str:
    if value is None:
        return "não coletado"
    if isinstance(value, float):
        return f"{value:.2f}".replace(".", ",")
    return f"{value:,}".replace(",", ".") if isinstance(value, int) else str(value)


def pct(part: int, total: int) -> str:
    return f"{round(100 * part / total)}%" if total else "—"


def long_date(moment: datetime) -> str:
    return f"{moment.day} de {MONTHS[moment.month - 1]} de {moment.year}"


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " e " + items[-1] if items else ""


def _lower_first(text: str) -> str:
    """Só a inicial em minúscula, para encaixar o título na frase sem perder siglas e nomes (Sophos, EDR)."""
    return text[:1].lower() + text[1:]


def _previous_value(evolution: list[dict[str, Any]], label: str) -> Any:
    return next((e["anterior"] for e in evolution if e["indicador"] == label), None)


# --- painel de indicadores ----------------------------------------------------------------


def panels(m: dict[str, Any], evolution: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    a, z = first(m, "acronis"), first(m, "zabbix")
    contracted = [c.get("dispositivos") for c in (m.get("contrato") or {}).values() if c.get("dispositivos")]
    if a:
        inv = a["inventario"]
        sessions = a.get("sessoes_remotas")
        rows = [("Dispositivos gerenciados", n(inv.get("gerenciados")),
                 "Registrados no console Acronis" + (f" ({contracted[0]} contratados)." if contracted else ".")),
                ("Protegidos", n(inv.get("protegidos")), "Agente ativo e proteção operacional."),
                ("Desprotegidos", n(inv.get("desprotegidos")), "Sem proteção ativa operacional — risco direto de contaminação."),
                ("Descobertos (sem agente)", n(inv.get("descobertos")), "Dispositivos identificados na rede ainda sem agente.")]
        if sessions:
            rows.append(("Sessões de acesso remoto", n(sessions["total"]), "Executadas por analistas autorizados ("
                         + "; ".join(f"{c} {u}" for u, c in sessions["por_usuario"].items()) + ")."))
        out.append({"titulo": "Endpoint Security — Inventário e Estado de Proteção", "linhas": rows})

        threats, inc, summary = a.get("ameacas"), a.get("incidentes_edr"), a.get("resumo_periodo") or {}
        rows = []
        if threats:
            rows += [("Ameaças detectadas e mitigadas (painel)", n(threats["automaticas"] + threats["manuais"]),
                      f"{pct(threats['automaticas'] + threats['manuais'], threats['total'])} mitigadas; situação atual do painel Acronis."),
                     ("Mitigações automáticas", n(threats["automaticas"]), "Contenção automática pela plataforma EDR."),
                     ("Mitigações manuais", n(threats["manuais"]), "Intervenção do time de operações."),
                     ("Ameaças não mitigadas", n(threats["nao_mitigadas"]), "Pendentes de tratamento." if threats["nao_mitigadas"] else "Nenhuma pendente.")]
        if summary.get("ameacas_mitigadas") is not None:
            rows.append(("Ameaças mitigadas no período", n(summary["ameacas_mitigadas"]), "Resumo de proteção do período."))
        if inc:
            prev = _previous_value(evolution, "Incidentes EDR")
            rows.append(("Incidentes EDR", n(inc["total"]), f"Em {len(inc['maquinas'])} dispositivos; {inc['automaticos']} mitigados automaticamente, "
                         f"{inc['manuais']} manualmente" + (f"; período anterior: {prev}." if prev is not None else ".")))
        for t in a.get("taticas") or []:
            if t["contagem"]:
                rows.append((f"Detecções MITRE — {t['nome_pt']}", n(t["contagem"]), f"Período anterior: {t['anterior']}."))
        if summary.get("urls_maliciosas_bloqueadas") is not None:
            rows.append(("Bloqueios de URLs maliciosas", n(summary["urls_maliciosas_bloqueadas"]), "Proteção Web — exposição a links nocivos/phishing."))
        if summary.get("perifericos_bloqueados") is not None:
            rows.append(("Bloqueios de periféricos", n(summary["perifericos_bloqueados"]), "Tentativas de uso de dispositivos externos barradas por política."))
        down = a["alertas"]["falhas_servico_protecao"]
        rows.append(("Falhas do serviço de proteção", n(down["ocorrencias"]),
                     f"Serviço parou de responder em {_join(down['maquinas'])}." if down["ocorrencias"] else "Nenhuma no período."))
        out.append({"titulo": "EDR — Ameaças, Incidentes e Controles", "linhas": rows})

        vuln, vm = a.get("vulnerabilidades"), a.get("maquinas_vulneraveis")
        if vuln:
            sev = vuln["por_severidade"]
            high = sev.get("critical", 0) + sev.get("high", 0)
            rows = [("Vulnerabilidades identificadas", n(vuln["total"]), f"Total ativo no parque, em {vuln['maquinas_afetadas']} máquinas."),
                    ("Críticas", n(sev.get("critical", 0)), "Exploração com potencial de comprometimento grave."),
                    ("Altas", n(sev.get("high", 0)), f"Somadas às críticas: {n(high)} ({pct(high, vuln['total'])} do total)."),
                    ("Médias", n(sev.get("medium", 0)), "—"),
                    ("Baixas / não classificadas", n(sev.get("low", 0) + sev.get("none", 0)),
                     f"{n(sev.get('low', 0))} baixas e {n(sev.get('none', 0))} sem classificação.")]
            note = ""
            if vm:
                note = (f"Perfil de risco por máquina: {vm['criticas']} em nível Crítico, {vm['altas']} em nível Alto, "
                        f"{vm['medias'] + vm['baixas']} em nível Médio/Baixo e {vm['protegidas'] + vm['sem_registro']} sem vulnerabilidades "
                        f"detectadas ({vm['protegidas']} protegidas, {vm['sem_registro']} sem registro).")
            if vuln.get("produtos_criticos"):
                note += " Softwares mais afetados por vulnerabilidades críticas: " + "; ".join(
                    f"{p['produto']} (ex.: {', '.join(p['cves'][:2])})" for p in vuln["produtos_criticos"][:5]) + "."
            out.append({"titulo": "Gestão de Vulnerabilidades", "linhas": rows, "nota": note.strip()})

        patches, missing, alerts = a.get("patches"), a.get("atualizacoes_faltantes"), a["alertas"]
        rows = []
        if patches:
            tried = patches["maquinas_instaladas"] + patches["maquinas_com_falha"]
            rows.append(("Máquinas com instalação de patch", n(tried), f"{patches['maquinas_instaladas']} concluídas, {patches['maquinas_com_falha']} "
                         f"com falha ({pct(patches['maquinas_com_falha'], tried)} de insucesso), {patches['maquinas_reinicio_pendente']} pendentes de reinício."))
        if missing:
            rows.append(("Atualizações faltantes", n(missing["total"]), f"{missing['seguranca']} de segurança, {missing['criticas']} críticas e {missing['outras']} de outras categorias."))
        sev = alerts["por_severidade"]
        rows.append(("Alertas no período", n(alerts["total"]), f"{sev['critical']} críticos · {sev['error']} erros · {sev['warning']} avisos · {sev['information']} informativos."))
        if alerts["offline"]["quantidade"]:
            rows.append(("Máquinas offline > 20/30 dias", n(alerts["offline"]["quantidade"]), "Ex.: " + ", ".join(
                f"{e['maquina']} ({e['dias']} dias)" for e in alerts["offline"]["exemplos"][:3] if e["dias"]) + "."))
        if alerts["pouco_espaco_disco"]["quantidade"]:
            rows.append(("Pouco espaço em disco", n(alerts["pouco_espaco_disco"]["quantidade"]), "Pode bloquear atualizações e o agente de segurança."))
        out.append({"titulo": "Patches e Alertas da Console", "linhas": rows})
    s = first(m, "sophos")
    if s:
        ep, health, alerts = s["endpoints"], s["saude"], s["alertas"]
        sev = alerts["por_severidade"]
        origins = _join([f"{p} ({q})" for p, q in (alerts.get("por_produto") or {}).items()])
        if not ep["total"]:
            rows = [("Endpoints gerenciados", "0", "Nenhum computador ou servidor deste cliente no Sophos Central."),
                    ("Alertas no período", n(alerts["total"]), f"{sev['alta']} alta · {sev['media']} média · {sev['baixa']} baixa"
                     + (f"; origem: {origins}." if origins else "."))]
            out.append({"titulo": "Sophos Central", "linhas": rows})
        else:
            rows = [("Endpoints gerenciados", n(ep["total"]), f"{ep['computadores']} computadores e {ep['servidores']} servidores no Sophos Central"
                     + (f"; {s['offline_agora']} offline na coleta." if s.get("offline_agora") else ".")),
                    ("Saúde boa", n(health["boa"]), f"{health['suspeita']} suspeita · {health['ruim']} ruim · {health['desconhecida']} desconhecida."),
                    ("Com ameaça ativa", n(s["ameacas_ativas"]["quantidade"]),
                     _join(s["ameacas_ativas"]["maquinas"][:4]) + "." if s["ameacas_ativas"]["quantidade"] else "Nenhum endpoint com ameaça ativa."),
                    ("Com item suspeito pendente", n((s.get("itens_suspeitos") or {}).get("quantidade")),
                     _join((s.get("itens_suspeitos") or {}).get("maquinas", [])[:4]) + " (ex.: PUA aguardando limpeza)."
                     if (s.get("itens_suspeitos") or {}).get("quantidade") else "Nenhum."),
                    ("Serviços de proteção com falha", n(s["servicos_com_falha"]["quantidade"]),
                     _join(s["servicos_com_falha"]["maquinas"][:4]) + "." if s["servicos_com_falha"]["quantidade"] else "Todos os serviços íntegros."),
                    ("Proteção contra adulteração desativada", n(s["adulteracao_desativada"]["quantidade"]),
                     "Agente pode ser desligado ou removido." if s["adulteracao_desativada"]["quantidade"] else "Ativa em todos os endpoints."),
                    ("Sem comunicação recente", n(s["sem_comunicacao"]["quantidade"]), "Não recebem atualizações nem políticas." if s["sem_comunicacao"]["quantidade"] else "—")]
            if s["isolados"]:
                rows.append(("Endpoints isolados", n(s["isolados"]), "Isolados da rede pelo Sophos Central."))
            rows.append(("Alertas no período", n(alerts["total"]), f"{sev['alta']} alta · {sev['media']} média · {sev['baixa']} baixa"
                         + (f"; origem: {origins}." if origins else ".")))
            out.append({"titulo": "Sophos Central — Proteção de Endpoints", "linhas": rows})
    if z:
        rows = [("Disponibilidade geral", f"{n(z['disponibilidade_geral'])}%" if z["disponibilidade_geral"] is not None else "não coletado",
                 "Média dos ativos monitorados pelo ping."),
                ("Ativos monitorados", n(z["hosts"]), f"{z['indisponiveis']} indisponíveis · {z['desativados']} desativados."),
                ("Alarmes disparados", n(z["alarmes_no_periodo"]), "Eventos de problema no período."),
                ("Problemas ativos", n(z["problemas_ativos"]), f"{z['problemas_graves']} de severidade alta ou desastre.")]
        if z["abaixo_95"]:
            rows.append(("Ativos abaixo de 95%", n(len(z["abaixo_95"])), _join([f"{x['host']} ({n(x['pct'])}%)" for x in z["abaixo_95"][:4]]) + "."))
        out.append({"titulo": "Monitoramento de Infraestrutura (NOCaaS)", "linhas": rows})
    return out


# --- textos --------------------------------------------------------------------------------


def _context(rec: dict[str, Any], m: dict[str, Any], evolution: list[dict[str, Any]]) -> tuple[str, str]:
    """(título, parágrafo de contexto de risco) de cada ponto de atenção."""
    a = first(m, "acronis") or {}
    key = rec["chave"]
    sophos_texts = {
        "sophos_ameacas": ("Ameaças ativas em endpoints (Sophos)", " Uma ameaça ativa indica malware ou comportamento malicioso ainda não "
                           "limpo: o equipamento pode estar comprometido e servir de ponto de propagação para a rede."),
        "sophos_servicos": ("Serviços de proteção do Sophos com falha", " Com os serviços parados, o endpoint deixa de detectar e bloquear "
                            "ameaças, mesmo aparecendo como gerenciado no console."),
        "sophos_suspeitos": ("Itens suspeitos pendentes (Sophos)", " Itens suspeitos, como ferramentas de administração remota ou "
                             "aplicativos indesejados, podem ser legítimos, mas também são usados por atacantes; a pendência precisa "
                             "de decisão do time."),
        "sophos_alertas_altos": ("Alertas de severidade alta (Sophos)", " Alertas de severidade alta indicam eventos que exigem análise do "
                                 "time de segurança."),
        "sophos_adulteracao": ("Proteção contra adulteração desativada", " Sem essa proteção, um usuário ou um malware com privilégios pode "
                               "desligar ou remover o agente de segurança."),
        "sophos_sem_comunicacao": ("Endpoints sem comunicação (Sophos)", " Esses equipamentos não recebem atualizações nem políticas e "
                                   "distorcem os indicadores do ambiente."),
    }
    if key in sophos_texts:
        title, risk = sophos_texts[key]
        return title, rec["ponto"] + risk
    alerts = a.get("alertas") or {}
    if key == "vulnerabilidades":
        v, vm = a["vulnerabilidades"], a.get("maquinas_vulneraveis") or {}
        high = v["por_severidade"].get("critical", 0) + v["por_severidade"].get("high", 0)
        products = _join([p["produto"] for p in v.get("produtos_criticos", [])[:4]])
        return ("Volume severo de vulnerabilidades ativas",
                f"O parque soma {n(v['total'])} vulnerabilidades, das quais {n(high)} são de criticidade Alta ou Crítica"
                + (f", e {vm.get('criticas')} máquinas estão classificadas em nível Crítico" if vm.get("criticas") else "") + ". "
                + (f"A concentração em {products} é especialmente relevante, pois são softwares usados diariamente e frequentemente "
                   "explorados por ataques via web e e-mail." if products else ""))
    if key == "patches":
        p = a["patches"]
        tried = p["maquinas_instaladas"] + p["maquinas_com_falha"]
        factors = []
        if alerts.get("pouco_espaco_disco", {}).get("quantidade"):
            factors.append(f"{alerts['pouco_espaco_disco']['quantidade']} dispositivos com pouco espaço livre em disco")
        if alerts.get("reinicio_necessario"):
            factors.append(f"{alerts['reinicio_necessario']} solicitações de reinicialização pendentes")
        return ("Insucesso na aplicação de patches",
                f"Das {tried} máquinas com instalação de atualizações no período, {p['maquinas_com_falha']} tiveram falha "
                f"({pct(p['maquinas_com_falha'], tried)}). Na prática, isso impede a correção automatizada das vulnerabilidades. "
                + (f"Entre os fatores observáveis na console estão {_join(factors)}; " if factors else "")
                + "a causa raiz das falhas precisa ser investigada.")
    if key == "desprotegidos":
        inv = a["inventario"]
        prev = _previous_value(evolution, "Endpoints desprotegidos")
        return ("Endpoints desprotegidos",
                f"{inv.get('desprotegidos')} máquinas gerenciadas estão sem proteção ativa operacional"
                + (f" (período anterior: {prev})" if prev is not None else "") + ". Um dispositivo desprotegido não detecta nem bloqueia "
                "ameaças e pode servir de porta de entrada para a contaminação do restante da rede."
                + (f" Há ainda {inv['descobertos']} dispositivos descobertos na rede sem agente instalado." if inv.get("descobertos") else ""))
    if key == "servico_protecao":
        d = alerts["falhas_servico_protecao"]
        times = "Foi registrada 1 ocorrência" if d["ocorrencias"] == 1 else f"Foram registradas {d['ocorrencias']} ocorrências"
        return ("Falhas no serviço de proteção",
                f"{times} em que o serviço de proteção parou de responder ({_join(d['maquinas'])}), "
                "exigindo reinicialização ou intervenção manual. Enquanto o serviço está parado, a estação fica sem proteção ativa.")
    if key == "offline":
        off = alerts["offline"]
        longest = max((e["dias"] or 0 for e in off["exemplos"]), default=0)
        return ("Máquinas inativas há mais de 30 dias",
                f"{off['quantidade']} endpoints estão há mais de 20/30 dias sem conectar à console"
                + (f", com casos de até {longest} dias" if longest else "") + ". Esses ativos distorcem os indicadores, ocupam licenças e, "
                "se voltarem à rede, retornarão sem atualizações.")
    if key == "disco":
        return ("Pouco espaço em disco",
                f"{alerts['pouco_espaco_disco']['quantidade']} dispositivos operam com pouco espaço livre, o que pode impedir "
                "atualizações do sistema e do agente de segurança.")
    if key == "taticas":
        tactics = [t for t in a.get("taticas") or [] if t["contagem"]]
        inc = a.get("incidentes_edr") or {}
        return ("Atividades suspeitas detectadas pelo EDR",
                "O EDR registrou detecções nas táticas " + _join([f"{t['nome_pt']} ({t['contagem']}; período anterior: {t['anterior']})" for t in tactics])
                + " do modelo MITRE ATT&CK, que descreve as etapas de um ataque. "
                + (f"Foram {inc.get('total')} incidentes em {len(inc.get('maquinas', []))} dispositivos, " if inc else "")
                + "o que indica usuários expostos a conteúdo malicioso, ainda que contido.")
    if key in ("backup_desatualizado", "backup_sem_plano"):
        return ("Backup", rec["ponto"] + " Sem backup em dia, uma falha de disco ou um ataque de ransomware pode causar perda definitiva de dados.")
    if key == "urls":
        return ("Exposição a sites maliciosos", rec["ponto"] + " Os bloqueios mostram que a proteção atua, mas também que os usuários "
                "seguem expostos a links nocivos e campanhas de phishing.")
    if key == "perifericos":
        return ("Uso de periféricos", rec["ponto"] + " A política impede vazamento de dados e entrada de malware por dispositivos externos.")
    if key == "disponibilidade":
        return ("Disponibilidade de ativos monitorados", rec["ponto"] + " Quedas recorrentes afetam a operação e merecem investigação de causa.")
    if key == "indisponiveis":
        return ("Ativos indisponíveis", rec["ponto"])
    if key == "alarmes":
        return ("Volume de alarmes", rec["ponto"] + " Excesso de alarmes gera ruído e dificulta enxergar os eventos realmente relevantes.")
    return (rec["ponto"], rec["acao"])


def narrative(m: dict[str, Any], evolution: list[dict[str, Any]], follow: list[dict[str, Any]]) -> dict[str, Any]:
    a, s, z = first(m, "acronis"), first(m, "sophos"), first(m, "zabbix")
    client, period = m.get("cliente"), m.get("periodo") or ""
    recs = m.get("recomendacoes") or []
    summary = []
    scope = []
    for contract in (m.get("contrato") or {}).values():
        if contract.get("produtos"):
            scope.append(_join(contract["produtos"]) + (f" ({contract['dispositivos']} dispositivos contratados)" if contract.get("dispositivos") else ""))
    areas = ["segurança de endpoints"] if a or (s and s["endpoints"]["total"]) else []
    if s and "Firewall" in (s["alertas"].get("por_produto") or {}):
        areas.append("segurança de rede")
    if z:
        areas.append("monitoramento de infraestrutura")
    p1 = f"Este relatório consolida os indicadores de {_join(areas) or 'segurança'} da {client} referentes a {period.lower()}."
    if scope:
        p1 += f" O escopo contratado abrange {_join(scope)}."
    if a:
        inv = a["inventario"]
        p1 += (f" O console Acronis registra {n(inv.get('gerenciados'))} dispositivos gerenciados, dos quais {n(inv.get('protegidos'))} "
               f"estão com proteção ativa e {n(inv.get('desprotegidos'))} encontram-se desprotegidos.")
    if s:
        ep, threats = s["endpoints"], s["ameacas_ativas"]["quantidade"]
        origins = _join([f"{p} ({q})" for p, q in (s["alertas"].get("por_produto") or {}).items()])
        if ep["total"]:
            p1 += (f" No Sophos Central são {n(ep['total'])} endpoints gerenciados ({n(ep['computadores'])} computadores e "
                   f"{n(ep['servidores'])} servidores), " + ("nenhum com ameaça ativa" if not threats else f"{n(threats)} com ameaça ativa")
                   + (f" e {n(s['itens_suspeitos']['quantidade'])} com item suspeito pendente."
                      if (s.get("itens_suspeitos") or {}).get("quantidade") else "."))
        else:
            p1 += (f" No Sophos Central, o período registrou {n(s['alertas']['total'])} alertas"
                   + (f" (origem: {origins})" if origins else "") + "; não há endpoints deste cliente na plataforma.")
    summary.append(p1)
    if a and (a.get("ameacas") or a.get("incidentes_edr")):
        threats, inc = a.get("ameacas"), a.get("incidentes_edr")
        parts = []
        if threats:
            ok = threats["nao_mitigadas"] == 0
            prev = _previous_value(evolution, "Ameaças não mitigadas")
            parts.append(f"Do ponto de vista de resposta a ameaças, o painel do Acronis registra {n(threats['total'])} ameaças, "
                         f"das quais {n(threats['automaticas'])} mitigadas automaticamente e {n(threats['manuais'])} com intervenção do time"
                         + (", sem nenhuma pendente" if ok else f", com {threats['nao_mitigadas']} ainda não mitigadas")
                         + (f" (período anterior: {prev} não mitigadas)" if prev is not None else "") + ".")
        if inc:
            prev = _previous_value(evolution, "Incidentes EDR")
            parts.append(f"No período foram registrados {n(inc['total'])} incidentes de EDR em {len(inc['maquinas'])} dispositivos"
                         + (f" (período anterior: {prev})" if prev is not None else "") + ".")
        execution = next((t for t in a.get("taticas") or [] if t["nome"] == "Execution" and t["contagem"]), None)
        if execution:
            parts.append(f"As detecções na tática MITRE ATT&CK \"Execução\" (tentativas de executar programas ou comandos suspeitos) "
                         f"somaram {execution['contagem']}, frente a {execution['anterior']} no período anterior.")
        summary.append(" ".join(parts))
    if z:
        summary.append(f"No monitoramento de infraestrutura, a disponibilidade geral foi de {n(z['disponibilidade_geral'])}% em {z['hosts']} ativos, "
                       f"com {n(z['alarmes_no_periodo'])} alarmes disparados e {z['problemas_ativos']} problemas ativos ao fim do período.")
    high = [r for r in recs if r["criticidade"] == "alta"]
    if high:
        titles = [_lower_first(_context(r, m, evolution)[0]) for r in high[:3]]
        summary.append(f"O principal risco do ambiente está em {titles[0]}: {high[0]['ponto']}"
                       + (f" Somam-se a isso {_join(titles[1:])}." if len(titles) > 1 else "")
                       + " Esses pontos estão detalhados e priorizados nas seções seguintes.")

    points = [{"titulo": t, "texto": text} for t, text in (_context(r, m, evolution) for r in recs if r["criticidade"] != "baixa")]
    pending = sum(1 for f in follow if f["status"] == "Pendente")
    closing = f"Em {period.lower()}, "
    good = []
    if a and a.get("ameacas") and a["ameacas"]["nao_mitigadas"] == 0:
        good.append("todas as ameaças registradas no painel estão mitigadas")
    if s and s["endpoints"]["total"] and not s["ameacas_ativas"]["quantidade"]:
        good.append("nenhum endpoint do Sophos Central apresenta ameaça ativa")
    if z and (z.get("disponibilidade_geral") or 0) >= 99:
        good.append(f"a disponibilidade geral ficou em {n(z['disponibilidade_geral'])}%")
    improved = [e["indicador"].lower() for e in evolution if e["leitura"] == "melhora"][:2]
    if improved:
        good.append("houve melhora em " + _join(improved))
    closing += (_join(good) + ". " if good else "o ambiente manteve a operação monitorada. ")
    if high:
        closing += "O risco, porém, segue concentrado em " + _join([_lower_first(_context(r, m, evolution)[0]) for r in high[:3]]) + ". "
    if follow:
        closing += (f"{pending} das {len(follow)} recomendações do ciclo anterior permanecem pendentes. " if pending else
                    "As recomendações do ciclo anterior foram tratadas. ")
    medium = next((r for r in recs if r["criticidade"] == "media"), None)
    if high:
        step = "tratar como prioridade imediata " + _lower_first(high[0]["acao"]).rstrip(".")
    elif medium:
        step = "como próximo passo " + _lower_first(medium["acao"]).rstrip(".")
    else:
        step = "a manutenção das boas práticas atuais"
    closing += f"A Contego recomenda {step} e permanece à disposição para apoiar a execução das ações."
    return {"sumario": summary, "pontos": points, "consideracoes": closing}


def build(m: dict[str, Any], evolution: list[dict[str, Any]], follow: list[dict[str, Any]], texts: dict[str, Any] | None = None,
          company: str = "Contego", logo: str = "", issued: datetime | None = None, by_ai: bool = False,
          previous_label: str | None = None) -> dict[str, Any]:
    texts = texts or narrative(m, evolution, follow)
    return {
        "cliente": m.get("cliente"), "competencia": m.get("periodo"), "emitido": long_date(issued or datetime.now()),
        "empresa": company, "logo": logo, "sumario": texts["sumario"], "paineis": panels(m, evolution),
        "pontos": texts["pontos"], "consideracoes": texts["consideracoes"], "por_ia": by_ai,
        "recomendacoes": [{**r, "rotulo": CRIT_LABEL[r["criticidade"]]} for r in m.get("recomendacoes") or []],
        "evolucao": evolution, "acompanhamento": follow, "avisos": m.get("avisos") or [],
        "periodo_anterior": previous_label,
    }

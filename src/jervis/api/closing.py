"""Relatórios de vários clientes e fechamento mensal.

O fechamento gera os relatórios do mês anterior de todos os clientes vinculados (um após o outro; a falha de um
não interrompe os demais), registra cada um em ``customer_reports`` como pendente de revisão e avisa a equipe
pelos canais de notificação configurados (Teams e/ou e-mail). O envio ao cliente é feito pela equipe depois da
aprovação (``jervis reviews approve``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from jervis.api import collect
from jervis.db import repository
from jervis.errors import JervisError
from jervis.security import redact

log = logging.getLogger(__name__)


@dataclass
class Outcome:
    customer: str
    resultado: str  # sucesso | parcial | falha
    run_dir: Path | None
    detalhe: str = ""  # motivo da falha ou avisos
    report_id: int | None = None


def previous_month(now: datetime | None = None) -> str:
    """Mês anterior ao de ``now`` (AAAA-MM): o que o fechamento do dia 1 relata."""
    first = (now or datetime.now()).replace(day=1)
    return f"{first - timedelta(days=1):%Y-%m}"


def resultado(statuses: dict[str, str]) -> str:
    """sucesso: todas as plataformas; falha: nenhuma; parcial: o resto."""
    values = list(statuses.values())
    if values and all(s == "sucesso" for s in values):
        return "sucesso"
    if not values or all(s == "falha" for s in values):
        return "falha"
    return "parcial"


def record(conn, run, period: collect.Period, origin: str, user: str | None) -> tuple[str, int]:
    """Registra a execução de um cliente para revisão; devolve (resultado, id do registro)."""
    statuses = {r.platform: r.status for r in run.results}
    outcome = resultado(statuses)
    problems = [f"{r.platform}: {r.status}" for r in run.results if r.status != "sucesso"]
    report_id = repository.record_report(conn, run.customer.id, f"{period.since:%Y-%m}" if period.monthly else None,
                                         period.label, str(run.run_dir), outcome, origin, user, "; ".join(problems) or None)
    return outcome, report_id


def run_customers(config, store, conn, customers: list[repository.Customer], period: collect.Period,
                  run_customer: Callable, formats: list[str] | None = None, ai: bool = False, origin: str = "manual",
                  user: str | None = None, emit: Callable[[str], None] = print) -> list[Outcome]:
    """Relatório de cada cliente, um após o outro, registrado para revisão (commit a cada cliente)."""
    outcomes = []
    for index, customer in enumerate(customers, 1):
        emit(f"[{index}/{len(customers)}] {customer.name}")
        try:
            run = run_customer(config, store, conn, str(customer.id), period=period, formats=formats, ai=ai, emit=emit)
        except Exception as exc:  # noqa: BLE001 - um erro inesperado num cliente não interrompe o fechamento
            reason = redact(str(exc)) if isinstance(exc, JervisError) else f"erro inesperado ({type(exc).__name__}): {redact(str(exc))[:300]}"
            if not isinstance(exc, JervisError):
                log.exception("Relatório de %s interrompido por erro inesperado", customer.name)
            emit(f"  FALHA: {reason}")
            report_id = repository.record_report(conn, customer.id, f"{period.since:%Y-%m}" if period.monthly else None,
                                                 period.label, None, "falha", origin, user, reason)
            conn.commit()
            outcomes.append(Outcome(customer.name, "falha", None, reason, report_id))
            continue
        outcome, report_id = record(conn, run, period, origin, user)
        conn.commit()
        problems = [f"{r.platform}: {r.status}" for r in run.results if r.status != "sucesso"]
        outcomes.append(Outcome(customer.name, outcome, run.run_dir, "; ".join(problems), report_id))
    return outcomes


def summary_message(period_label: str, outcomes: list[Outcome], limit: int = 30) -> tuple[str, str, str]:
    """(assunto, texto, situação geral) do aviso à equipe."""
    counts = {k: sum(1 for o in outcomes if o.resultado == k) for k in ("sucesso", "parcial", "falha")}
    pending = counts["sucesso"] + counts["parcial"]
    status = "falha" if outcomes and counts["falha"] == len(outcomes) else "parcial" if counts["falha"] or counts["parcial"] else "sucesso"
    subject = (f"[Jervis3000] Fechamento {period_label}: {pending} relatório(s) aguardando revisão"
               + (f", {counts['falha']} com falha" if counts["falha"] else ""))
    lines = [f"Relatórios de {len(outcomes)} cliente(s): {counts['sucesso']} completos, {counts['parcial']} com limitações "
             f"(alguma plataforma falhou) e {counts['falha']} sem dados.", ""]
    for label, kind in (("Com falha (não gerados ou sem dados)", "falha"), ("Com limitações (revisar com atenção)", "parcial")):
        items = [o for o in outcomes if o.resultado == kind]
        if items:
            lines.append(f"{label}:")
            lines += [f"  - {o.customer}: {o.detalhe}" for o in items[:limit]]
            if len(items) > limit:
                lines.append(f"  ... e mais {len(items) - limit}")
            lines.append("")
    lines += ["Revisar: jervis reviews list", "Aprovar: jervis reviews approve <cliente>   |   Rejeitar: jervis reviews reject <cliente> --reason \"...\""]
    return subject, "\n".join(lines), status


def done_marker(output_dir: str | Path, month: str) -> Path:
    """Registro de que o fechamento do mês foi feito: evita repetir quando o agendamento dispara de novo."""
    return Path(output_dir) / "fechamentos" / f"{month}.json"


def close_month(config, store, conn, notifier, run_customer: Callable, reportable: Callable, month: str | None = None,
                origin: str = "manual", user: str | None = None, emit: Callable[[str], None] = print,
                now: datetime | None = None) -> list[Outcome]:
    """Fechamento do mês (padrão: o anterior): relatórios de todos os clientes vinculados, registro para revisão e
    aviso à equipe. Uma falha ao avisar não desfaz nada: aparece no terminal."""
    period = collect.month(month or previous_month(now), now=now)
    customers = reportable(conn)
    emit(f"Fechamento de {period.short}: {len(customers)} cliente(s)")
    outcomes = run_customers(config, store, conn, customers, period, run_customer, origin=origin, user=user, emit=emit)
    subject, body, status = summary_message(period.short, outcomes)
    if config is not None:
        marker = done_marker(config.settings.output_dir, f"{period.since:%Y-%m}")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({"competencia": f"{period.since:%Y-%m}", "concluido_em": datetime.now().isoformat(timespec="seconds"),
                                      "origem": origin, "usuario": user,
                                      "resultados": {o.customer: o.resultado for o in outcomes}}, ensure_ascii=False, indent=1),
                          encoding="utf-8")
    emit("")
    emit(subject)
    if notifier is not None:
        errors = notifier.send_message(subject, body, status)
        for channel, error in errors.items():
            emit(f"Aviso à equipe por {channel} não enviado: {error}")
        if not errors and notifier.channels():
            emit(f"Aviso enviado por: {', '.join(notifier.channels())}")
    return outcomes

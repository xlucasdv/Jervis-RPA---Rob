"""Relatório geral de um cliente por API: lê no banco os serviços dele, coleta cada um e gera os relatórios."""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Callable

from jervis.api import ApiError, collect, factory
from jervis.collection import save_result
from jervis.collectors.models import CollectionResult, Issue, now_iso
from jervis.config import AppConfig
from jervis.credentials import CredentialStore
from jervis.db import repository
from jervis.errors import CredentialError, IssueCategory
from jervis.fileutil import atomic_write_text
from jervis.reports.slides import load_notes
from jervis.runner import consolidate_run, generate_run_reports

COLLECTABLE = ("acronis", "sophos", "zabbix")


@dataclasses.dataclass
class CustomerRun:
    customer: repository.Customer
    run_dir: Path
    results: list[CollectionResult]
    report: dict
    files: dict


NOTES_DIR = Path("notas")


def default_notes_path(customer: str, period: collect.Period) -> Path | None:
    """notas/<cliente>/<AAAA-MM>.yaml (relatório mensal) ou notas/<cliente>/notas.yaml."""
    folder = NOTES_DIR / slug(customer)
    candidates = ([folder / f"{period.since:%Y-%m}.yaml"] if period.monthly else []) + [folder / "notas.yaml"]
    return next((c for c in candidates if c.is_file()), None)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "cliente"


def reportable_customers(conn) -> list[repository.Customer]:
    """Clientes ativos vinculados a pelo menos um serviço coletável por API (Acronis, Sophos ou Zabbix), por nome."""
    services = {s.slug: s for s in repository.list_services(conn)}
    return [c for c in repository.list_customers(conn) if c.active
            and any(slug in services and services[slug].class_identifier in COLLECTABLE for slug in c.services)]


def run_customer(config: AppConfig, store: CredentialStore, conn, customer_ref: str,
                 period: collect.Period | None = None, formats: list[str] | None = None,
                 emit: Callable[[str], None] = print, builder: Callable = factory.build,
                 notes: Path | None = None, ai: bool = False) -> CustomerRun:
    period = period or collect.last_days(30)
    customer = repository.find_customer(conn, customer_ref)
    services = {s.slug: s for s in repository.list_services(conn)}
    links = [services[s] for s in customer.services if s in services and services[s].class_identifier in COLLECTABLE]
    if not links:
        raise repository.RecordError(
            f"O cliente '{customer.name}' não está vinculado a Acronis, Sophos nem Zabbix. Use 'jervis customers link'.")

    run_dir = Path(config.settings.output_dir) / "clientes" / slug(customer.name) / datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    emit(f"Relatório de {customer.name} ({period.label}): {', '.join(s.slug for s in links)}")
    results = []
    for service in links:
        name_on = customer.name_on(service.slug)
        emit(f"  · {service.slug}: coletando '{name_on}' pela API...")
        try:
            api = builder(service, store)
            if service.class_identifier == "acronis":
                result = collect.collect_acronis(api, service.slug, name_on, period)
            elif service.class_identifier == "sophos":
                result = collect.collect_sophos(api, service.slug, name_on, period)
            else:
                result = collect.collect_zabbix(api, service.slug, name_on, period)
        except (ApiError, CredentialError) as exc:
            result = CollectionResult(platform=service.slug, kind=service.class_identifier)
            category = IssueCategory.CONFIGURATION if isinstance(exc, CredentialError) else IssueCategory.UNAVAILABLE
            result.issues.append(Issue("api", category, str(exc)))
            result.finished_at = now_iso()
        save_result(result, run_dir)
        counts = ", ".join(f"{k}: {v}" for k, v in result.counts().items()) or "nenhum dado"
        emit(f"    [{result.status.upper()}] {counts}")
        for issue in result.issues:
            emit(f"    {issue.severity}: {issue.message}")
        results.append(result)

    kind = "Relatório Mensal" if period.monthly else "Relatório Geral"
    settings = dataclasses.replace(config.settings, report_title=f"{kind} – {customer.name}")
    notes = notes or default_notes_path(customer.name, period)
    if notes and notes.is_file():
        emit(f"  Notas da equipe: {notes}")
    meta = {"cliente": customer.name, "tipo": kind, "periodo": period.label, "periodo_curto": period.short,
            "competencia": f"{period.since:%Y-%m}" if period.monthly else None,
            "parcial": period.monthly and period.until.day != 1,  # mês em andamento (termina hoje, não no dia 1)
            "contrato": {s.slug: customer.contracts[s.slug] for s in links if s.slug in customer.contracts},
            "resumos": {r.platform: r.summary for r in results}, "notas": load_notes(notes)}
    results_data = [r.to_dict() for r in results]
    report = consolidate_run(results_data, run_dir, settings, emit)
    formats = formats if formats is not None else settings.report_formats
    output = generate_run_reports(report, run_dir, settings, formats,
                                  emit, meta=meta, basename="relatorio_mensal")
    files = dict(output.files) if output else {}
    files.update(write_customer_documents(results_data, report, meta, run_dir, settings, emit, ai=ai, store=store,
                                          pdf="pdf" in formats))
    atomic_write_text(run_dir / "cliente.json", json.dumps(
        {"cliente": customer.name, "id": customer.id, "desk_manager_id": customer.desk_manager_id,
         "servicos": {s.slug: customer.name_on(s.slug) for s in links}, "periodo": period.label, "gerado_em": now_iso()},
        ensure_ascii=False, indent=2))
    return CustomerRun(customer, run_dir, results, report, files)


def write_customer_documents(results: list[dict], report: dict, meta: dict, run_dir: Path, settings, emit,
                             ai: bool = False, store=None, pdf: bool = True) -> dict[str, list[Path]]:
    """Indicadores (metricas.json), resumo em Markdown e relatório executivo (HTML e PDF)."""
    from jervis.reports import executive, metrics, summary_md
    from jervis.reports.html import render_executive
    from jervis.reports.pdf import A4_PORTRAIT_CM, write_pdf
    from jervis.reports.slides import logo_data_uri
    from jervis.security import redact

    data = metrics.compute(results, report, meta)
    metrics.save(data, run_dir)
    before = metrics.previous(run_dir)
    evolution, follow = metrics.evolution(data, before), metrics.follow_up(data, before)
    files: dict[str, list[Path]] = {}

    md = summary_md.render(data, evolution, follow)
    files["md"] = [atomic_write_text(run_dir / "resumo.md", redact(md))]
    emit("  Resumo: resumo.md")

    texts, by_ai = None, False
    if ai:
        from jervis.reports import ai as ai_writer
        try:
            texts = ai_writer.write_executive(md, store, settings)
            by_ai = True
            emit("  Texto do relatório executivo redigido pela IA (números conferidos com os dados).")
        except ai_writer.AiError as exc:
            emit(f"  Atenção: texto da IA não usado ({exc}); relatório executivo com o texto padrão.")
    document = executive.build(data, evolution, follow, texts, settings.report_company, logo_data_uri(settings.report_logo),
                               by_ai=by_ai, previous_label=(before or {}).get("periodo_curto"))
    html = redact(render_executive(document))
    files["executivo"] = [atomic_write_text(run_dir / "relatorio_executivo.html", html)]
    if not pdf:
        emit("  Relatório executivo: relatorio_executivo.html")
        return files
    try:
        files["executivo"].append(write_pdf(html, run_dir / "relatorio_executivo.pdf", settings, A4_PORTRAIT_CM, 1.6))
        emit("  Relatório executivo: relatorio_executivo.pdf")
    except Exception as exc:  # noqa: BLE001 - o PDF depende do navegador; o HTML já foi gerado
        emit(f"  Relatório executivo PDF: não gerado — {exc}")
    return files

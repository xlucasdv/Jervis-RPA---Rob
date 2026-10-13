"""Clientes das plataformas x cadastro do Jervis (jervis services clients) e relatório de todos (--all)."""

import contextlib
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from jervis import cli
from jervis.api import ApiError, collect, run, sync
from jervis.config import AppConfig, Settings
from jervis.db import repository
from jervis.db.repository import Customer, Service


def customers():
    return [
        Customer(1, "MERCOS", None, services=["acronis"]),
        Customer(2, "Passebus", None, services=["acronis"], external={"acronis": "PASSEBUS Transportes"}),
        Customer(3, "Core - DF", None),
        Customer(4, "Antigo", None, services=["acronis"]),
        Customer(5, "Repetido", None), Customer(6, "Repetido", None),
    ]


def test_compare_with_the_platform():
    names = ["mercos", "PASSEBUS Transportes", "CORE - DF", "Novo Cliente", "Repetido"]
    rows = {r.name: r for r in sync.compare(names, customers(), "acronis")}
    assert rows["mercos"].status == sync.LINKED and rows["mercos"].customer.id == 1  # sem diferenciar maiúsculas
    assert rows["PASSEBUS Transportes"].status == sync.LINKED  # pelo nome na plataforma do vínculo
    assert rows["CORE - DF"].status == sync.UNLINKED and rows["CORE - DF"].customer.id == 3
    assert rows["Novo Cliente"].status == sync.NEW and rows["Novo Cliente"].customer is None
    assert rows["Repetido"].status == sync.AMBIGUOUS
    assert [c.name for c in sync.orphans(names, customers(), "acronis")] == ["Antigo"]


def test_import_creates_customers_and_links(monkeypatch):
    calls = []
    monkeypatch.setattr(repository, "add_customer", lambda conn, name, dm: calls.append(("add", name)) or 10)
    monkeypatch.setattr(repository, "link", lambda conn, ref, slug: calls.append(("link", ref, slug)))
    rows = sync.compare(["Novo Cliente", "CORE - DF", "MERCOS", "Repetido"], customers(), "acronis")
    assert sync.import_missing(None, rows, "acronis") == [("Novo Cliente", True), ("CORE - DF", False)]
    assert calls == [("add", "Novo Cliente"), ("link", "10", "acronis"), ("link", "3", "acronis")]


def test_reportable_customers_only_with_api_services(monkeypatch):
    monkeypatch.setattr(repository, "list_services", lambda conn: [
        Service(1, "acronis", "https://a", "acronis", {}), Service(2, "dm", "https://d", "deskmanager", {})])
    monkeypatch.setattr(repository, "list_customers", lambda conn: [
        Customer(1, "A", None, services=["acronis"]), Customer(2, "B", None, services=["dm"]), Customer(3, "C", None)])
    assert [c.name for c in run.reportable_customers(None)] == ["A"]


def test_report_all_continues_after_a_failure(monkeypatch, capsys):
    recorded = []
    monkeypatch.setattr(repository, "record_report", lambda conn, cid, comp, period, run_dir, result, origin, user, note=None:
                        recorded.append((cid, result, run_dir)) or len(recorded))
    monkeypatch.setattr(cli, "_db", lambda config: contextlib.nullcontext(SimpleNamespace(commit=lambda: None)))
    monkeypatch.setattr(cli, "_store", lambda config: None)
    monkeypatch.setattr(cli, "_audit", lambda *a, **k: None)
    people = [Customer(1, "A", None), Customer(2, "B", None), Customer(3, "C", None)]

    def fake_run(config, store, conn, ref, **kwargs):
        if ref == "2":
            raise ApiError("[acronis] Cliente 'B' não encontrado no Acronis.")
        status = "sucesso" if ref == "1" else "parcial"
        return SimpleNamespace(results=[SimpleNamespace(platform="acronis", status=status)], run_dir=Path(f"out/{ref}"))

    def fake_run_with_customer(config, store, conn, ref, **kwargs):
        run = fake_run(config, store, conn, ref, **kwargs)
        run.customer = people[int(ref) - 1]
        return run

    config = AppConfig(settings=Settings(), platforms={})
    period = collect.month("2026-09", now=datetime(2026, 10, 13).astimezone())
    assert cli._report_all(config, lambda conn: people, fake_run_with_customer, period, None, False) == 2
    out = capsys.readouterr().out
    assert "3 cliente(s): A, B, C" in out and "[2/3] B" in out and "FALHA: [acronis] Cliente 'B'" in out
    summary = [line.split()[:3] for line in out.split("Resumo:")[1].strip().splitlines()[1:4]]
    assert summary == [["#1", "A", "sucesso"], ["#2", "B", "falha"], ["#3", "C", "parcial"]]
    assert [(cid, result) for cid, result, _ in recorded] == [(1, "sucesso"), (2, "falha"), (3, "parcial")]
    assert recorded[1][2] is None  # falha: sem pasta
    assert "2 relatório(s) aguardando revisão" in out

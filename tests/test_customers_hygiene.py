"""Limpeza do cadastro: clientes inativos (fora do fechamento), junção de cadastros duplicados e sugestões."""

import contextlib

import pytest

from jervis import cli
from jervis.api import run, sync
from jervis.config import AppConfig, Settings
from jervis.db import repository
from jervis.db.repository import Customer, RecordError, Service


def test_probable_duplicates_ignore_generic_words_and_different_states():
    names = ["Agile", "AGILE2 CONSULTING", "BIOCAL", "Biocal Workspace", "Coren RS", "COREN - MT", "CORE - DF", "CORE/RN",
             "Prefeitura Municipal de Santa Bárbara d´Oeste/SP", "Santa Barbara d'oeste", "PREFEITURA DE JALES - SP",
             "Prefeitura de Votuporanga", "Unimed Lages", "UNIMED PLANALTO NORTE", "IMA", "CAP"]
    people = [Customer(i, n, None) for i, n in enumerate(names)]
    pairs = {(a.name, b.name) for a, b in sync.probable_duplicates(people)}
    assert pairs == {("Agile", "AGILE2 CONSULTING"), ("BIOCAL", "Biocal Workspace"),
                     ("Prefeitura Municipal de Santa Bárbara d´Oeste/SP", "Santa Barbara d'oeste")}


def test_test_customers_by_name():
    assert [n for n in ["CONTEGO - POC", "SESC-POC", "Buschle - Trial", "Lab", "Assessment - UPN", "Contego Security", "Labor S.A."]
            if sync.looks_like_test(n)] == ["CONTEGO - POC", "SESC-POC", "Buschle - Trial", "Lab", "Assessment - UPN"]


def test_inactive_customers_are_left_out_of_the_month_close(monkeypatch):
    monkeypatch.setattr(repository, "list_services", lambda conn: [Service(1, "sophos", "https://s", "sophos", {})])
    monkeypatch.setattr(repository, "list_customers", lambda conn: [
        Customer(1, "CERMISSOES", None, services=["sophos"]),
        Customer(2, "SESC-POC", None, services=["sophos"], active=False, inactive_reason="POC encerrada")])
    assert [c.name for c in run.reportable_customers(None)] == ["CERMISSOES"]


def test_merge_refuses_customers_on_the_same_service(monkeypatch):
    people = {"34": Customer(34, "Aguas do Pantanal", None, services=["sophos"]),
              "84": Customer(84, "Águas do Pantanal Saneamento Ambiental", None, services=["sophos"])}
    monkeypatch.setattr(repository, "find_customer", lambda conn, ref: people[ref])
    with pytest.raises(RecordError, match=r"mesmo serviço \(sophos\).*Desative"):
        repository.merge_customers(None, "34", "84")
    with pytest.raises(RecordError, match="mesmo cliente"):
        repository.merge_customers(None, "34", "34")


class FakeCursor:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        self.log.append((" ".join(sql.split()), params))


def test_merge_moves_links_history_and_desk_manager(monkeypatch):
    source = Customer(32, "Agile", "DM-9", services=["sophos"])
    target = Customer(25, "AGILE2 CONSULTING", None, services=["acronis-us"])
    merged = Customer(25, "AGILE2 CONSULTING", "DM-9", services=["acronis-us", "sophos"], external={"sophos": "Agile"})
    calls = iter([source, target, merged])
    monkeypatch.setattr(repository, "find_customer", lambda conn, ref: next(calls))
    log = []
    conn = type("Conn", (), {"cursor": lambda self: FakeCursor(log)})()
    gone, kept, moved = repository.merge_customers(conn, "32", "25")
    assert gone.name == "Agile" and kept.external == {"sophos": "Agile"} and moved == ["sophos"]
    sql = [s for s, _ in log]
    assert sql[0].startswith("UPDATE customer_services SET customer_id = %s, external_name = COALESCE(external_name, %s)")
    assert log[0][1] == (25, "Agile", 32)  # o vínculo leva o nome antigo como nome na plataforma
    assert any(s.startswith("UPDATE customer_reports SET customer_id") for s in sql)
    assert log[-1] == ("DELETE FROM customers WHERE id = %s", (32,))
    assert ("UPDATE customers SET desk_manager_id = %s WHERE id = %s", ("DM-9", 25)) in log


def test_customers_list_shows_inactive(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_db", lambda config: contextlib.nullcontext(None))
    monkeypatch.setattr(repository, "list_customers", lambda conn: [
        Customer(1, "CERMISSOES", None, services=["sophos"]), Customer(2, "SESC-POC", None, services=["sophos"], active=False)])
    assert cli.cmd_customers_list(None, AppConfig(settings=Settings(), platforms={})) == 0
    out = capsys.readouterr().out
    assert [line.split()[2] for line in out.splitlines()[1:3]] == ["sim", "não"]
    assert "2 cliente(s), 1 inativo(s) (fora do fechamento mensal)." in out

"""Fechamento mensal (relatórios de todos os clientes do mês anterior), aviso à equipe e revisão antes do envio."""

import contextlib
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from jervis import cli
from jervis.api import ApiError, closing
from jervis.config import AppConfig, NotificationConfig, ScheduleConfig, Settings
from jervis.credentials import CredentialStore
from jervis.db import repository
from jervis.db.repository import Customer, CustomerReport
from jervis.notify import WEBHOOK_SECRET, Notifier

NOW = datetime(2026, 10, 1, 6, 0).astimezone()


def test_previous_month_and_result():
    assert closing.previous_month(datetime(2026, 10, 1, 6, 0)) == "2026-09"
    assert closing.previous_month(datetime(2027, 1, 1, 6, 0)) == "2026-12"
    assert closing.resultado({"acronis": "sucesso", "zabbix": "sucesso"}) == "sucesso"
    assert closing.resultado({"acronis": "sucesso", "zabbix": "falha"}) == "parcial"
    assert closing.resultado({"acronis": "falha"}) == "falha" and closing.resultado({}) == "falha"


class FakeConn:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def fake_runner(failing=(), partial=()):
    seen = []

    def run_customer(config, store, conn, ref, period=None, formats=None, ai=False, emit=print):
        seen.append(period)
        if ref in failing:
            raise ApiError(f"[sophos] Cliente {ref} não encontrado no Sophos Central.")
        status = "parcial" if ref in partial else "sucesso"
        results = [SimpleNamespace(platform="acronis", status="sucesso"),
                   SimpleNamespace(platform="sophos", status="falha" if status == "parcial" else "sucesso")]
        return SimpleNamespace(customer=SimpleNamespace(id=int(ref), name=f"C{ref}"), results=results, run_dir=Path(f"out/{ref}"))
    return run_customer, seen


def test_month_close_generates_records_and_notifies(monkeypatch):
    recorded = []
    monkeypatch.setattr(repository, "record_report", lambda conn, cid, comp, period, run_dir, result, origin, user, note=None:
                        recorded.append(dict(cid=cid, comp=comp, run_dir=run_dir, result=result, origin=origin, note=note)) or len(recorded))
    run_customer, seen = fake_runner(failing={"2"}, partial={"3"})
    messages = []
    notifier = SimpleNamespace(send_message=lambda subject, body, status: messages.append((subject, body, status)) or {},
                               channels=lambda: ["webhook"])
    conn, lines = FakeConn(), []
    people = [Customer(1, "C1", None), Customer(2, "C2", None), Customer(3, "C3", None)]
    outcomes = closing.close_month(None, None, conn, notifier, run_customer, lambda c: people, origin="agendamento:fechamento_mensal",
                                   user="CONTEGO\\svc", emit=lines.append, now=NOW)
    # mês anterior, fechado (não parcial)
    assert all(p.short == "Setembro/2026" and p.monthly and p.until == datetime(2026, 10, 1).astimezone() for p in seen)
    assert [o.resultado for o in outcomes] == ["sucesso", "falha", "parcial"] and conn.commits == 3
    assert [r["comp"] for r in recorded] == ["2026-09"] * 3 and recorded[1]["run_dir"] is None
    assert recorded[2]["note"] == "sophos: falha" and recorded[0]["origin"] == "agendamento:fechamento_mensal"
    subject, body, status = messages[0]
    assert subject == "[Jervis3000] Fechamento Setembro/2026: 2 relatório(s) aguardando revisão, 1 com falha"
    assert status == "parcial" and "C2: [sophos] Cliente 2 não encontrado" in body and "C3: sophos: falha" in body
    assert "jervis reviews list" in body and "Aviso enviado por: webhook" in lines


def test_month_close_reports_notification_failure(monkeypatch):
    monkeypatch.setattr(repository, "record_report", lambda *a, **k: 1)
    run_customer, _ = fake_runner()
    notifier = SimpleNamespace(send_message=lambda *a: {"webhook": "NotificationError: URL do webhook não cadastrada"},
                               channels=lambda: ["webhook"])
    lines = []
    closing.close_month(None, None, FakeConn(), notifier, run_customer, lambda c: [Customer(1, "C1", None)], emit=lines.append, now=NOW)
    assert "Aviso à equipe por webhook não enviado: NotificationError: URL do webhook não cadastrada" in lines


# --- aviso pelo Teams -------------------------------------------------------------------


def test_send_message_posts_teams_card(memory_keyring):
    store = CredentialStore()
    store.set_secret(WEBHOOK_SECRET, "https://example.webhook.office.com/workflows/abc")
    posted = []

    def urlopen(request, timeout):
        posted.append(json.loads(request.data))
        return contextlib.nullcontext(SimpleNamespace(status=202))

    notifier = Notifier(NotificationConfig(webhook=True, webhook_format="teams"), store, urlopen=urlopen)
    assert notifier.channels() == ["webhook"]
    assert notifier.send_message("Fechamento Setembro/2026", "linha 1\nlinha 2", "parcial") == {}
    card = posted[0]["attachments"][0]["content"]
    assert card["body"][0]["text"] == "Fechamento Setembro/2026" and card["body"][0]["color"] == "Warning"
    assert Notifier(None, store).send_message("x", "y") == {"notificacao": "nenhum canal configurado (seção notifications: webhook e/ou email)"}


# --- revisão ---------------------------------------------------------------------------------


def report(status="pendente", run_dir="out/cermissoes/20261001-060000"):
    return CustomerReport(12, 40, "CERMISSOES", "2026-09", "Setembro de 2026", run_dir, "sucesso", status,
                          "agendamento:fechamento_mensal", "CONTEGO\\svc", datetime(2026, 10, 1, 6, 5))


@pytest.fixture
def review_env(monkeypatch, tmp_path):
    reviewed, audits = [], []
    monkeypatch.setattr(cli, "_db", lambda config: contextlib.nullcontext(None))
    monkeypatch.setattr(cli, "_audit", lambda config, event, **d: audits.append((event, d)))
    monkeypatch.setattr(cli, "actor", lambda: {"usuario": "CONTEGO\\lucas", "maquina": "PC"})
    folder = tmp_path / "cermissoes"
    folder.mkdir()
    (folder / "relatorio_executivo.pdf").write_bytes(b"%PDF")
    monkeypatch.setattr(repository, "find_report", lambda conn, ref, month=None: report(run_dir=str(folder)))
    monkeypatch.setattr(repository, "review_report", lambda conn, rid, status, who, note=None: reviewed.append((rid, status, who, note)))
    return reviewed, audits, folder


def test_approve_records_reviewer_and_lists_files(review_env, capsys):
    reviewed, audits, folder = review_env
    args = SimpleNamespace(report="CERMISSOES", month=None, note="conferido")
    assert cli.cmd_reviews_approve(args, AppConfig(settings=Settings(), platforms={})) == 0
    assert reviewed == [(12, "aprovado", "CONTEGO\\lucas", "conferido")]
    out = capsys.readouterr().out
    assert "Relatório #12 de CERMISSOES (2026-09) aprovado por CONTEGO\\lucas." in out
    assert str(folder / "relatorio_executivo.pdf") in out
    assert audits[0][0] == "relatorio_aprovado" and audits[0][1]["revisao"] == 12


def test_reject_requires_reason_and_suggests_regenerating(review_env, capsys):
    reviewed, audits, _ = review_env
    config = AppConfig(settings=Settings(), platforms={})
    with pytest.raises(Exception, match="motivo"):
        cli.cmd_reviews_reject(SimpleNamespace(report="CERMISSOES", month=None, reason="  "), config)
    assert cli.cmd_reviews_reject(SimpleNamespace(report="#12", month=None, reason="dados do Zabbix incompletos"), config) == 0
    assert reviewed == [(12, "rejeitado", "CONTEGO\\lucas", "dados do Zabbix incompletos")]
    assert 'jervis customers report "CERMISSOES" --month 2026-09' in capsys.readouterr().out


def test_reviews_list_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_db", lambda config: contextlib.nullcontext(None))
    monkeypatch.setattr(repository, "list_reports", lambda conn, status, month: [report()])
    assert cli.cmd_reviews_list(SimpleNamespace(status="pendente", month=None), AppConfig(settings=Settings(), platforms={})) == 0
    out = capsys.readouterr().out
    assert "#12" in out and "CERMISSOES" in out and "2026-09" in out and "pendente" in out and "1 relatório(s)." in out


def test_schedule_task_runs_the_month_close(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli, "_month_close", lambda config, month, origin, notify=True: calls.append((month, origin)) or 0)
    schedule = ScheduleConfig(name="fechamento_mensal", frequency="monthly", day=1, times=["06:00"], task="relatorios_clientes")
    assert cli._run_schedule(AppConfig(settings=Settings(output_dir=str(tmp_path)), platforms={}), schedule) == 0
    assert calls == [(None, "agendamento:fechamento_mensal")]  # None = mês anterior


def test_month_close_rejects_future_month():
    with pytest.raises(Exception, match="ainda não começou"):
        cli.cmd_month_close(SimpleNamespace(month="2999-01", no_notify=True), AppConfig(settings=Settings(), platforms={}))


# --- primeiro dia útil e fechamento uma vez por mês --------------------------------------------


def test_business_days():
    from datetime import date

    from jervis.business_days import easter, first_business_day, is_business_day

    assert [easter(y) for y in (2026, 2027, 2028)] == [date(2026, 4, 5), date(2027, 3, 28), date(2028, 4, 16)]
    assert first_business_day(2026, 11) == date(2026, 11, 3)  # 1º domingo, 2 Finados
    assert first_business_day(2027, 1) == date(2027, 1, 4)  # 1º feriado (sexta) + fim de semana
    assert first_business_day(2026, 12) == date(2026, 12, 1)
    assert not is_business_day(date(2027, 2, 9)) and not is_business_day(date(2026, 4, 3))  # Carnaval, Sexta-feira Santa


def test_first_business_day_schedule():
    from jervis import scheduling
    from jervis.config import parse_config

    config = parse_config({"platforms": {}, "schedules": {"fechamento_mensal": {
        "frequency": "monthly", "day": "primeiro dia útil", "times": ["09:00"], "task": "relatorios_clientes"}}})
    schedule = config.schedules["fechamento_mensal"]
    assert schedule.day == "primeiro_dia_util"
    assert scheduling.next_run(schedule, datetime(2026, 10, 13, 10, 0)) == datetime(2026, 11, 3, 9, 0)
    assert scheduling.describe(schedule) == "mensalmente no primeiro dia útil às 09:00"
    assert scheduling.create_commands(schedule, Path("x.cmd"))[0].endswith("/SC DAILY /ST 09:00")  # o Agendador não conhece dia útil
    assert not scheduling.is_due(schedule, datetime(2026, 11, 2).date()) and scheduling.is_due(schedule, datetime(2026, 11, 4).date())


def schedule_at(when, monkeypatch, tmp_path):
    """Executa o agendamento do fechamento como se fosse ``when``; devolve as chamadas ao fechamento."""
    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return when

    monkeypatch.setattr(cli, "datetime", Fixed)
    monkeypatch.setattr(closing, "datetime", Fixed)
    calls = []
    monkeypatch.setattr(cli, "_month_close", lambda config, month, origin, notify=True: calls.append(origin) or 0)
    schedule = ScheduleConfig(name="fechamento_mensal", frequency="monthly", day="primeiro_dia_util", times=["09:00"],
                              task="relatorios_clientes")
    assert cli._run_schedule(AppConfig(settings=Settings(output_dir=str(tmp_path)), platforms={}), schedule) == 0
    return calls


def test_scheduled_close_runs_once_from_the_first_business_day(monkeypatch, tmp_path, capsys):
    assert schedule_at(datetime(2026, 11, 2, 9, 0), monkeypatch, tmp_path) == []  # Finados: ainda não
    assert "ainda não é o primeiro dia útil" in capsys.readouterr().out
    assert schedule_at(datetime(2026, 11, 3, 9, 0), monkeypatch, tmp_path) == ["agendamento:fechamento_mensal"]
    closing.done_marker(tmp_path, "2026-10").parent.mkdir(parents=True)
    closing.done_marker(tmp_path, "2026-10").write_text("{}", encoding="utf-8")
    assert schedule_at(datetime(2026, 11, 4, 9, 0), monkeypatch, tmp_path) == []  # já feito: não repete
    assert "Fechamento de 2026-10 já feito" in capsys.readouterr().out


def test_close_month_writes_the_done_marker(monkeypatch, tmp_path):
    monkeypatch.setattr(repository, "record_report", lambda *a, **k: 1)
    run_customer, _ = fake_runner(partial={"2"})
    config = AppConfig(settings=Settings(output_dir=str(tmp_path)), platforms={})
    closing.close_month(config, None, FakeConn(), None, run_customer, lambda c: [Customer(1, "C1", None), Customer(2, "C2", None)],
                        emit=lambda line: None, now=NOW)
    marker = json.loads(closing.done_marker(tmp_path, "2026-09").read_text(encoding="utf-8"))
    assert marker["competencia"] == "2026-09" and marker["resultados"] == {"C1": "sucesso", "C2": "parcial"}

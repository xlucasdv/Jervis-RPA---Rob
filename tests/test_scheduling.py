import subprocess
from datetime import datetime

import pytest

from jervis import scheduling
from jervis.config import AppConfig, ScheduleConfig, Settings, parse_config
from jervis.errors import ConfigError


def sched(**kw):
    base = dict(name="diaria", frequency="daily", times=["07:00"])
    return ScheduleConfig(**{**base, **kw})


# --- regra de horários --------------------------------------------------------------

@pytest.mark.parametrize(
    "schedule, after, expected",
    [
        (sched(times=["07:00", "18:00"]), datetime(2026, 10, 6, 6, 0), datetime(2026, 10, 6, 7, 0)),
        (sched(times=["07:00", "18:00"]), datetime(2026, 10, 6, 7, 0), datetime(2026, 10, 6, 18, 0)),  # estritamente depois
        (sched(times=["07:00", "18:00"]), datetime(2026, 10, 6, 19, 0), datetime(2026, 10, 7, 7, 0)),
        # 06/10/2026 é terça-feira
        (sched(frequency="weekly", days=["mon", "thu"], times=["08:00"]), datetime(2026, 10, 6, 9, 0), datetime(2026, 10, 8, 8, 0)),
        (sched(frequency="weekly", days=["tue"], times=["08:00"]), datetime(2026, 10, 6, 9, 0), datetime(2026, 10, 13, 8, 0)),
        (sched(frequency="hourly", every_hours=4, start="06:00"), datetime(2026, 10, 6, 11, 0), datetime(2026, 10, 6, 14, 0)),
        (sched(frequency="hourly", every_hours=4, start="06:00"), datetime(2026, 10, 6, 23, 0), datetime(2026, 10, 7, 2, 0)),
        # 5h não divide 24: 08,13,18,23,04 e recomeça às 08 do dia seguinte
        (sched(frequency="hourly", every_hours=5, start="08:00"), datetime(2026, 10, 7, 4, 30), datetime(2026, 10, 7, 8, 0)),
        (sched(frequency="hourly", every_hours=5, start="08:00"), datetime(2026, 10, 6, 23, 30), datetime(2026, 10, 7, 4, 0)),
    ],
)
def test_next_run(schedule, after, expected):
    assert scheduling.next_run(schedule, after) == expected


def test_describe():
    assert scheduling.describe(sched(times=["07:00", "18:00"])) == "diariamente às 07:00, 18:00"
    assert scheduling.describe(sched(frequency="weekly", days=["mon", "sat"])) == "semanalmente (seg, sáb) às 07:00"
    assert scheduling.describe(sched(frequency="hourly", every_hours=4, start="06:00")) == "a cada 4 hora(s) a partir das 06:00"


# --- configuração -------------------------------------------------------------------

def test_schedule_config_parsing_accepts_aliases_and_unquoted_times():
    config = parse_config({
        "platforms": {"zabbix": {"url": "https://z.local"}},
        "schedules": {
            "manha": {"frequency": "diaria", "times": [420, "18:30"]},  # 420 = 07:00 lido pelo YAML sem aspas
            "semana": {"frequency": "semanal", "days": ["qui", "seg"], "times": "08:00", "platforms": ["zabbix"]},
            "horas": {"frequency": "hourly", "every_hours": 6},
        },
    })
    assert config.schedules["manha"].times == ["07:00", "18:30"]
    assert config.schedules["semana"].days == ["mon", "thu"] and config.schedules["semana"].times == ["08:00"]
    assert config.schedules["horas"].start == "00:00"


@pytest.mark.parametrize(
    "schedule, message",
    [
        ({"frequency": "mensal", "times": ["07:00"]}, "frequency"),
        ({"frequency": "daily"}, "ao menos um horário"),
        ({"frequency": "daily", "times": ["25:00"]}, "horário inválido"),
        ({"frequency": "weekly", "times": ["07:00"]}, "days"),
        ({"frequency": "weekly", "times": ["07:00"], "days": ["sexta"]}, "days"),
        ({"frequency": "hourly", "every_hours": 24}, "every_hours"),
        ({"frequency": "daily", "times": ["07:00"], "platforms": ["nagios"]}, "não cadastrada"),
        ({"frequency": "daily", "times": ["07:00"], "retries": -1}, "retries"),
        ({"frequency": "daily", "times": ["07:00"], "horario": "x"}, "desconhecida"),
    ],
)
def test_schedule_config_validation(schedule, message):
    with pytest.raises(ConfigError, match=message):
        parse_config({"platforms": {"zabbix": {"url": "https://z.local"}}, "schedules": {"s": schedule}})


def test_schedules_survive_save_roundtrip(tmp_path):
    from jervis.config import load_config, save_config

    config = parse_config({"platforms": {}, "schedules": {"s": {"frequency": "weekly", "days": ["fri"], "times": ["07:00"]}}})
    loaded = load_config(save_config(config, tmp_path / "c.yaml"))
    assert loaded.schedules["s"] == config.schedules["s"]


# --- Agendador de Tarefas do Windows --------------------------------------------------

def test_task_commands(tmp_path):
    wrapper = tmp_path / "diaria.cmd"
    daily = scheduling.create_commands(sched(times=["07:00", "18:00"]), wrapper)
    assert len(daily) == 2
    assert '/TN "Jervis3000\\diaria-0700"' in daily[0] and "/SC DAILY /ST 07:00" in daily[0]
    assert f'/TR "\\"{wrapper.resolve()}\\""' in daily[0]
    weekly = scheduling.create_commands(sched(name="semanal", frequency="weekly", days=["mon", "thu"]), wrapper)
    assert weekly == [weekly[0]] and '/TN "Jervis3000\\semanal"' in weekly[0] and "/SC WEEKLY /D MON,THU /ST 07:00" in weekly[0]
    hourly = scheduling.create_commands(sched(name="h", frequency="hourly", every_hours=4, start="06:00"), wrapper)
    assert "/SC DAILY /ST 06:00 /RI 240 /DU 23:59" in hourly[0]


def test_wrapper_script(tmp_path):
    config_path = tmp_path / "config" / "platforms.yaml"
    wrapper = scheduling.write_wrapper(sched(), config_path, workdir=tmp_path)
    text = wrapper.read_text(encoding="utf-8")
    assert wrapper == tmp_path / "agendamentos" / "diaria.cmd"
    assert f'cd /d "{tmp_path.resolve()}"' in text
    assert f'-m jervis -c "{config_path.resolve()}" schedule run diaria' in text
    assert '>> "logs\\agendamento-diaria.log" 2>&1' in text


class FakeSchtasks:
    def __init__(self, tasks=(), fail=False):
        self.tasks = set(tasks)
        self.calls = []
        self.fail = fail

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if self.fail:
            return subprocess.CompletedProcess(args, 1, "", "ERRO: Acesso negado.")
        if isinstance(args, list) and args[1] == "/Query":
            out = "".join(f'"\\{t}","07/10/2026 07:00:00","Pronto"\n' for t in sorted(self.tasks))
            out += '"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","N/A","Pronto"\n'
            return subprocess.CompletedProcess(args, 0, out, "")
        if isinstance(args, list) and args[1] == "/Delete":
            self.tasks.discard(args[-1])
        return subprocess.CompletedProcess(args, 0, "SUCESSO", "")


def app_config(tmp_path, schedules):
    config = parse_config({"platforms": {}, "schedules": schedules})
    config.path = tmp_path / "platforms.yaml"
    return config


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="registro real só no Windows")
def test_install_registers_active_schedules(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = app_config(tmp_path, {
        "diaria": {"frequency": "daily", "times": ["07:00", "18:00"]},
        "desligada": {"frequency": "daily", "times": ["03:00"], "enabled": False},
    })
    fake = FakeSchtasks()
    commands = scheduling.install(config, run=fake)
    assert len(commands) == 2 and fake.calls == commands
    assert (tmp_path / "agendamentos" / "diaria.cmd").exists()
    assert not (tmp_path / "agendamentos" / "desligada.cmd").exists()


def test_install_dry_run_and_failures(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = app_config(tmp_path, {"diaria": {"frequency": "daily", "times": ["07:00"]}})
    fake = FakeSchtasks()
    assert len(scheduling.install(config, run=fake, dry_run=True)) == 1
    assert fake.calls == [] and not (tmp_path / "agendamentos").exists()
    with pytest.raises(ConfigError, match="não cadastrado"):
        scheduling.install(config, ["outra"], run=fake, dry_run=True)
    with pytest.raises(ConfigError, match="Nenhum agendamento ativo"):
        scheduling.install(app_config(tmp_path, {}), run=fake, dry_run=True)
    if __import__("sys").platform == "win32":
        with pytest.raises(scheduling.SchedulerError, match="Acesso negado"):
            scheduling.install(config, run=FakeSchtasks(fail=True))


def test_installed_tasks_and_uninstall():
    fake = FakeSchtasks({"Jervis3000\\diaria-0700", "Jervis3000\\diaria-1800", "Jervis3000\\fim-de-semana", "Jervis3000\\diaria-extra"})
    assert scheduling.installed_tasks(fake) == fake.tasks
    removed = scheduling.uninstall(["diaria"], run=fake)
    assert removed == ["Jervis3000\\diaria-0700", "Jervis3000\\diaria-1800"]  # "diaria-extra" é outro agendamento
    assert scheduling.uninstall(run=fake) == ["Jervis3000\\diaria-extra", "Jervis3000\\fim-de-semana"]


# --- agendador interno ----------------------------------------------------------------

def test_serve_runs_schedules_in_order():
    now = [datetime(2026, 10, 6, 6, 59)]
    config = AppConfig(settings=Settings(), platforms={}, schedules={
        "a": sched(name="a", times=["07:00"]), "b": sched(name="b", times=["07:30"]),
        "off": sched(name="off", times=["07:10"], enabled=False),
    })
    ran, messages = [], []

    def sleep(seconds):
        now[0] = now[0] + __import__("datetime").timedelta(seconds=seconds)

    def run(schedule):
        ran.append((schedule.name, now[0]))

    assert scheduling.serve(lambda: config, run, emit=messages.append, clock=lambda: now[0], sleep=sleep, max_runs=2) == 2
    assert ran == [("a", datetime(2026, 10, 6, 7, 0)), ("b", datetime(2026, 10, 6, 7, 30))]
    assert "Próxima execução: 'a'" in messages[0]


def test_serve_stops_without_active_schedules():
    config = AppConfig(settings=Settings(), platforms={}, schedules={})
    messages = []
    assert scheduling.serve(lambda: config, lambda s: None, emit=messages.append) == 0
    assert "Nenhum agendamento ativo" in messages[0]

"""Agendamento automático das coletas (Feature 7.2).

Dois modos, com a mesma regra de horários:
  * **Agendador de Tarefas do Windows** (recomendado): ``jervis schedule install`` cria uma
    tarefa por agendamento/horário. Sobrevive a reinicializações e não exige processo aberto.
  * **Agendador interno** (``jervis schedule serve``): processo em primeiro plano que dispara
    as coletas nos horários; útil fora do Windows ou sem permissão no Agendador de Tarefas.

Cada tarefa chama um script ``agendamentos/<nome>.cmd`` que entra na pasta do projeto (onde
ficam ``logs/`` e ``output/``) e executa ``jervis schedule run <nome>``.
"""

from __future__ import annotations

import csv
import io
import math
import re
import subprocess
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable

from jervis.business_days import first_business_day
from jervis.config import FIRST_BUSINESS_DAY, WEEKDAYS, AppConfig, ScheduleConfig
from jervis.errors import ConfigError, JervisError

TASK_FOLDER = "Jervis3000"
WRAPPER_DIR = Path("agendamentos")
_DAY_LABEL = dict(zip(WEEKDAYS, ("seg", "ter", "qua", "qui", "sex", "sáb", "dom")))

Runner = Callable[..., subprocess.CompletedProcess]


class SchedulerError(JervisError):
    """Falha ao registrar ou consultar tarefas no Agendador de Tarefas."""


# --- regra de horários ----------------------------------------------------------------


def _at(day: datetime, hhmm: str) -> datetime:
    hour, minute = map(int, hhmm.split(":"))
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0)


def next_run(schedule: ScheduleConfig, after: datetime) -> datetime:
    """Próximo horário de execução estritamente depois de ``after``."""
    candidates: list[datetime] = []
    if schedule.frequency == "monthly":
        year, month = after.year, after.month
        for _ in range(3):
            number = first_business_day(year, month).day if schedule.day == FIRST_BUSINESS_DAY else schedule.day
            day = after.replace(year=year, month=month, day=number)
            candidates += [t for t in (_at(day, hhmm) for hhmm in schedule.times) if t > after]
            if candidates:
                break
            year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    elif schedule.frequency in ("daily", "weekly"):
        for offset in range(8):
            day = after + timedelta(days=offset)
            if schedule.frequency == "weekly" and WEEKDAYS[day.weekday()] not in schedule.days:
                continue
            candidates += [t for t in (_at(day, hhmm) for hhmm in schedule.times) if t > after]
            if candidates:
                break
    else:
        # A cada N horas a partir de "start", recomeçando a contagem todo dia em "start".
        step = schedule.every_hours
        for offset in (-1, 0, 1):
            anchor = _at(after + timedelta(days=offset), schedule.start)
            for k in range(math.ceil(24 / step)):
                t = anchor + timedelta(hours=k * step)
                if t < anchor + timedelta(hours=24) and t > after:
                    candidates.append(t)
    return min(candidates)


def describe(schedule: ScheduleConfig) -> str:
    times = ", ".join(schedule.times)
    if schedule.frequency == "daily":
        return f"diariamente às {times}"
    if schedule.frequency == "monthly":
        when = "no primeiro dia útil" if schedule.day == FIRST_BUSINESS_DAY else f"no dia {schedule.day}"
        return f"mensalmente {when} às {times}"
    if schedule.frequency == "weekly":
        return f"semanalmente ({', '.join(_DAY_LABEL[d] for d in schedule.days)}) às {times}"
    return f"a cada {schedule.every_hours} hora(s) a partir das {schedule.start}"


# --- Agendador de Tarefas do Windows ------------------------------------------------------


def task_folder(env: str | None = None) -> str:
    return f"{TASK_FOLDER}\\{env}" if env else TASK_FOLDER


def task_names(schedule: ScheduleConfig, env: str | None = None) -> list[str]:
    folder = task_folder(env)
    if schedule.frequency == "hourly" or len(schedule.times) == 1:
        return [f"{folder}\\{schedule.name}"]
    return [f"{folder}\\{schedule.name}-{t.replace(':', '')}" for t in schedule.times]


def create_commands(schedule: ScheduleConfig, wrapper: Path, env: str | None = None) -> list[str]:
    """Linhas de comando do schtasks (uma por horário; 'a cada N horas' usa repetição diária)."""
    target = f'/TR "\\"{wrapper.resolve()}\\""'
    if schedule.frequency == "hourly":
        # Disparo diário em "start" repetido a cada N horas durante o dia: mesma regra de next_run().
        return [
            f'schtasks /Create /F /TN "{task_names(schedule, env)[0]}" {target} /SC DAILY /ST {schedule.start} '
            f"/RI {schedule.every_hours * 60} /DU 23:59"
        ]
    days = (f" /D {','.join(d.upper() for d in schedule.days)}" if schedule.frequency == "weekly"
            else f" /D {schedule.day}" if schedule.frequency == "monthly" and schedule.day != FIRST_BUSINESS_DAY else "")
    # O Agendador não conhece dia útil (e o disparo mensal aceita um só dia): o primeiro dia útil dispara todo dia
    # e a tarefa só trabalha a partir dele, uma vez por mês (ver is_due e o registro do fechamento feito)
    trigger = "DAILY" if schedule.day == FIRST_BUSINESS_DAY else {"weekly": "WEEKLY", "monthly": "MONTHLY"}.get(schedule.frequency, "DAILY")
    return [
        f'schtasks /Create /F /TN "{name}" {target} /SC {trigger}{days} /ST {hhmm}'
        for name, hhmm in zip(task_names(schedule, env), schedule.times)
    ]


def is_due(schedule: ScheduleConfig, today: date) -> bool:
    """Para o primeiro dia útil: o disparo diário só vale a partir dele (dias antes, no mesmo mês, não)."""
    return schedule.day != FIRST_BUSINESS_DAY or today >= first_business_day(today.year, today.month)


def catch_up_command(task: str) -> str:
    """Liga "executar assim que possível se um horário agendado for perdido" (PC desligado no horário: roda quando
    o usuário entrar). O schtasks não tem essa opção na criação; o PowerShell (ScheduledTasks) ajusta depois, só
    nas configurações: regravar a tarefa inteira (-InputObject) falha com gatilho mensal."""
    folder, name = task.rsplit("\\", 1)
    where = f"-TaskPath '\\{folder}\\' -TaskName '{name}'"
    script = (f"$s = (Get-ScheduledTask {where}).Settings; $s.StartWhenAvailable = $true; "
              f"Set-ScheduledTask {where} -Settings $s | Out-Null")
    return f'powershell -NoProfile -NonInteractive -Command "{script}"'


def write_wrapper(
    schedule: ScheduleConfig, config_path: Path, workdir: Path | None = None, env: str | None = None
) -> Path:
    """Script chamado pela tarefa: entra na pasta do projeto e registra a saída em logs/."""
    workdir = (workdir or Path.cwd()).resolve()
    wrapper = workdir / WRAPPER_DIR / (env or "") / f"{schedule.name}.cmd"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    log_file = Path("logs") / (env or "") / f"agendamento-{schedule.name}.log"
    env_arg = f" --env {env}" if env else ""
    wrapper.write_text(
        "@echo off\r\n"
        "rem Gerado por 'jervis schedule install'. Não edite: será sobrescrito.\r\n"
        "chcp 65001 >nul\r\n"
        f'cd /d "{workdir}"\r\n'
        f'if not exist "{log_file.parent}" mkdir "{log_file.parent}"\r\n'
        f'"{Path(sys.executable).resolve()}" -m jervis -c "{config_path.resolve()}"{env_arg} schedule run {schedule.name} '
        f'>> "{log_file}" 2>&1\r\n',
        encoding="utf-8",
    )
    return wrapper


def installed_tasks(run: Runner = subprocess.run, env: str | None = None) -> set[str]:
    """Nomes das tarefas do Jervis3000 (do ambiente ``env``) registradas no Agendador de Tarefas."""
    try:
        proc = run(["schtasks", "/Query", "/FO", "CSV", "/NH"], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise SchedulerError("Agendador de Tarefas (schtasks) indisponível neste sistema.") from exc
    if proc.returncode != 0:
        raise SchedulerError(f"Não foi possível consultar o Agendador de Tarefas: {(proc.stderr or proc.stdout).strip()}")
    names = set()
    prefix = task_folder(env) + "\\"
    for row in csv.reader(io.StringIO(proc.stdout)):
        name = row[0].lstrip("\\") if row else ""
        # Sem ambiente, ignora as subpastas de ambientes (Jervis3000\hml\...).
        if name.startswith(prefix) and "\\" not in name[len(prefix):]:
            names.add(name)
    return names


def install(
    config: AppConfig, names: list[str] | None = None, run: Runner = subprocess.run, dry_run: bool = False
) -> list[str]:
    """Registra os agendamentos ativos; devolve os comandos executados (ou que seriam, em ``dry_run``)."""
    if sys.platform != "win32" and not dry_run:
        raise SchedulerError("O registro automático só é suportado no Windows. Use 'jervis schedule serve'.")
    if config.path is None:
        raise ConfigError("Arquivo de configuração não identificado.")
    schedules = _select(config, names)
    env = config.environment
    commands = []
    for schedule in schedules:
        wrapper = (write_wrapper(schedule, config.path, env=env) if not dry_run
                   else Path.cwd() / WRAPPER_DIR / (env or "") / f"{schedule.name}.cmd")
        steps = create_commands(schedule, wrapper, env) + [catch_up_command(t) for t in task_names(schedule, env)]
        for command in steps:
            commands.append(command)
            if not dry_run:
                proc = run(command, capture_output=True, text=True)
                if proc.returncode != 0:
                    raise SchedulerError(f"Falha ao criar a tarefa ({schedule.name}): {(proc.stderr or proc.stdout).strip()}")
    return commands


def uninstall(names: list[str] | None = None, run: Runner = subprocess.run, env: str | None = None) -> list[str]:
    """Remove as tarefas do Jervis3000 do ambiente (todas, ou só as dos agendamentos ``names``)."""
    removed = []
    for task in sorted(installed_tasks(run, env)):
        if names and not any(_belongs(task, name) for name in names):
            continue
        proc = run(["schtasks", "/Delete", "/F", "/TN", task], capture_output=True, text=True)
        if proc.returncode != 0:
            raise SchedulerError(f"Falha ao remover a tarefa {task}: {(proc.stderr or proc.stdout).strip()}")
        removed.append(task)
    return removed


def _belongs(task: str, schedule_name: str) -> bool:
    r"""A tarefa é do agendamento? ("Jervis3000\diaria" ou "Jervis3000\diaria-0700")."""
    base = task.rsplit("\\", 1)[1]
    return base == schedule_name or re.fullmatch(rf"{re.escape(schedule_name)}-\d{{4}}", base) is not None


def _select(config: AppConfig, names: list[str] | None) -> list[ScheduleConfig]:
    if names:
        unknown = [n for n in names if n not in config.schedules]
        if unknown:
            raise ConfigError(f"Agendamento(s) não cadastrado(s): {', '.join(unknown)}.")
        return [config.schedules[n] for n in names]
    active = [s for s in config.schedules.values() if s.enabled]
    if not active:
        raise ConfigError("Nenhum agendamento ativo em 'schedules' no arquivo de configuração.")
    return active


# --- agendador interno ------------------------------------------------------------------


def serve(
    load_config: Callable[[], AppConfig],
    run_schedule: Callable[[ScheduleConfig], object],
    emit: Callable[[str], None] = print,
    clock: Callable[[], datetime] = datetime.now,
    sleep: Callable[[float], None] = time.sleep,
    max_runs: int | None = None,
) -> int:
    """Executa os agendamentos nos horários, em primeiro plano. Relê a configuração a cada ciclo."""
    runs = 0
    while max_runs is None or runs < max_runs:
        active = [s for s in load_config().schedules.values() if s.enabled]
        if not active:
            emit("Nenhum agendamento ativo; encerrando.")
            return runs
        when, schedule = min(((next_run(s, clock()), s) for s in active), key=lambda item: item[0])
        emit(f"Próxima execução: '{schedule.name}' ({describe(schedule)}) em {when:%d/%m/%Y %H:%M}. Ctrl+C para sair.")
        while (remaining := (when - clock()).total_seconds()) > 0:
            sleep(min(remaining, 60))  # acorda periodicamente: Ctrl+C responde rápido
        run_schedule(schedule)
        runs += 1
    return runs

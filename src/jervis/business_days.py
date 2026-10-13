"""Dias úteis no Brasil: segunda a sexta, fora os feriados nacionais, a Sexta-feira Santa e o Carnaval.

Usado pelo fechamento mensal agendado para o primeiro dia útil do mês. Feriados estaduais e municipais não entram.
"""

from __future__ import annotations

from datetime import date, timedelta

# (mês, dia): Confraternização, Tiradentes, Trabalho, Independência, Aparecida, Finados, República,
# Consciência Negra (nacional desde 2024) e Natal
FIXED_HOLIDAYS = ((1, 1), (4, 21), (5, 1), (9, 7), (10, 12), (11, 2), (11, 15), (11, 20), (12, 25))


def easter(year: int) -> date:
    """Domingo de Páscoa (algoritmo de Meeus/Jones/Butcher, calendário gregoriano)."""
    a, b, c = year % 19, year // 100, year % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    m = (32 + 2 * e + 2 * i - h - k) % 7
    n = (a + 11 * h + 22 * m) // 451
    month = (h + m - 7 * n + 114) // 31
    day = (h + m - 7 * n + 114) % 31 + 1
    return date(year, month, day)


def holidays(year: int) -> set[date]:
    sunday = easter(year)
    movable = {sunday - timedelta(days=48), sunday - timedelta(days=47),  # Carnaval (segunda e terça)
               sunday - timedelta(days=2)}  # Sexta-feira Santa
    return {date(year, m, d) for m, d in FIXED_HOLIDAYS} | movable


def is_business_day(day: date) -> bool:
    return day.weekday() < 5 and day not in holidays(day.year)


def first_business_day(year: int, month: int) -> date:
    day = date(year, month, 1)
    while not is_business_day(day):
        day += timedelta(days=1)
    return day

"""Interpretação de valores exibidos nas telas (datas, durações, tamanhos).

As plataformas exibem valores formatados para leitura humana, no idioma do perfil
do usuário: "06/10/2026 09:00", "Oct 6, 2026 8:01 AM", "há 2 horas", "1 h 5 min",
"1,5 GB". Estas funções os convertem para valores comparáveis; quando não
reconhecem o formato, retornam ``None`` (o texto original é sempre preservado).
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta

from jervis.collectors.table import normalize_label

DATE_ORDERS = ("auto", "dmy", "mdy")

_MONTHS = {
    "jan": 1, "janeiro": 1, "january": 1,
    "fev": 2, "fevereiro": 2, "feb": 2, "february": 2,
    "mar": 3, "marco": 3, "march": 3,
    "abr": 4, "abril": 4, "apr": 4, "april": 4,
    "mai": 5, "maio": 5, "may": 5,
    "jun": 6, "junho": 6, "june": 6,
    "jul": 7, "julho": 7, "july": 7,
    "ago": 8, "agosto": 8, "aug": 8, "august": 8,
    "set": 9, "setembro": 9, "sep": 9, "sept": 9, "september": 9,
    "out": 10, "outubro": 10, "oct": 10, "october": 10,
    "nov": 11, "novembro": 11, "november": 11,
    "dez": 12, "dezembro": 12, "dec": 12, "december": 12,
}

_UNITS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "seg": 1, "segundo": 1, "segundos": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60, "minuto": 60, "minutos": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600, "hora": 3600, "horas": 3600,
    "d": 86400, "day": 86400, "days": 86400, "dia": 86400, "dias": 86400,
    "w": 604800, "week": 604800, "weeks": 604800, "semana": 604800, "semanas": 604800,
    "mes": 2592000, "meses": 2592000, "month": 2592000, "months": 2592000, "mo": 2592000,
    "y": 31536000, "year": 31536000, "years": 31536000, "ano": 31536000, "anos": 31536000,
}

_SIZE_UNITS = {"b": 0, "bytes": 0, "kb": 1, "kib": 1, "mb": 2, "mib": 2, "gb": 3, "gib": 3, "tb": 4, "tib": 4, "pb": 5, "pib": 5}

NEVER_WORDS = frozenset({"never", "nunca", "nenhum", "none", "not backed up", "sem backup"})

_TIME = r"(?P<hour>\d{1,2})[:h](?P<minute>\d{2})(?::(?P<second>\d{2}))?\s*(?P<ampm>am|pm)?"


def is_never(text: str | None) -> bool:
    return bool(text) and normalize_label(text) in NEVER_WORDS


def parse_datetime(text: str | None, now: datetime | None = None, order: str = "auto") -> datetime | None:
    """Converte uma data exibida na tela em ``datetime`` local (sem fuso). ``None`` se não reconhecer."""
    if not text or is_never(text):
        return None
    now = now or datetime.now()
    raw = text.strip().lower()
    for parser in (_parse_iso, _parse_relative, _parse_numeric, _parse_month_name, _parse_time_only):
        try:
            value = parser(raw, now, order)
        except ValueError:  # data impossível (ex.: 31/02)
            value = None
        if value is not None:
            return value
    return None


def to_iso(value: datetime | None) -> str | None:
    """ISO 8601 com o fuso local (as telas exibem horário local)."""
    return value.astimezone().isoformat(timespec="minutes") if value else None


def parse_duration(text: str | None) -> int | None:
    """'1 h 5 min' / '00:12:30' / '45 s' → segundos."""
    if not text:
        return None
    raw = text.strip().lower()
    clock = re.fullmatch(r"(\d+):(\d{2})(?::(\d{2}))?", raw)
    if clock:
        a, b, c = clock.groups()
        return int(a) * 3600 + int(b) * 60 + int(c) if c else int(a) * 60 + int(b)
    # Zabbix usa "M" maiúsculo para meses ("1M 2d") e "m" para minutos.
    raw = re.sub(r"(\d)\s*M\b", r"\1mo", text.strip())
    total, found = 0.0, False
    for number, unit in re.findall(r"(\d+(?:[.,]\d+)?)\s*([a-z]+)", _ascii(raw)):
        if unit not in _UNITS:
            return None
        total += float(number.replace(",", ".")) * _UNITS[unit]
        found = True
    return round(total) if found else None


def parse_percent(text: str | None) -> float | None:
    """'99.8500%' / '99,85 %' → 99.85."""
    if not text:
        return None
    match = re.fullmatch(r"\s*([\d.,]+)\s*%\s*", text)
    return _parse_number(match.group(1)) if match else None


def parse_size(text: str | None) -> int | None:
    """'1,5 GB' / '850 MB' / '1.234,5 MB' → bytes (base 1024, como as ferramentas de backup)."""
    if not text:
        return None
    match = re.fullmatch(r"\s*([\d.,\s]*\d)\s*([a-zA-Z]+)\s*", text)
    if not match or match.group(2).lower() not in _SIZE_UNITS:
        return None
    number = _parse_number(match.group(1).replace(" ", ""))
    return None if number is None else round(number * 1024 ** _SIZE_UNITS[match.group(2).lower()])


# --- datas --------------------------------------------------------------------------


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()


def _strip(text: str) -> str:
    """Minúsculas, sem acentos, sem pontuação irrelevante ('6 de out. de 2026, às 08:01' → '6 out 2026 08:01')."""
    text = _ascii(text)
    text = re.sub(r"[,.]", " ", text)
    text = re.sub(r"\b(de|as|at|em|on)\b", " ", text)
    return " ".join(text.split())


def _time_of(match: re.Match | None) -> tuple[int, int, int]:
    if not match or match.group("hour") is None:
        return 0, 0, 0
    hour, minute = int(match.group("hour")), int(match.group("minute"))
    second = int(match.group("second") or 0)
    ampm = match.group("ampm")
    if ampm == "pm" and hour < 12:
        hour += 12
    elif ampm == "am" and hour == 12:
        hour = 0
    return hour, minute, second


def _parse_iso(raw: str, now: datetime, order: str) -> datetime | None:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}([t ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?(z|[+-]\d{2}:?\d{2})?", raw):
        return None
    value = datetime.fromisoformat(raw.replace("z", "+00:00"))
    if value.tzinfo:  # converte para o horário local, como as demais datas
        value = value.astimezone().replace(tzinfo=None)
    return value


def _parse_relative(raw: str, now: datetime, order: str) -> datetime | None:
    text = _strip(raw)
    if text in ("agora", "just now", "now", "agora mesmo"):
        return now
    m = re.fullmatch(r"(?:ha\s+)?(\d+|um|uma|an|a)\s+([a-z]+)(?:\s+(?:ago|atras))?", text)
    if m and (text.startswith("ha ") or text.endswith(("ago", "atras"))):
        amount = 1 if m.group(1) in ("um", "uma", "an", "a") else int(m.group(1))
        unit = _UNITS.get(m.group(2))
        if unit:
            return now - timedelta(seconds=amount * unit)
    m = re.fullmatch(r"(hoje|today|ontem|yesterday)\s*(?:" + _TIME + r")?", text)
    if m:
        base = now if m.group(1) in ("hoje", "today") else now - timedelta(days=1)
        h, mi, s = _time_of(m)
        return base.replace(hour=h, minute=mi, second=s, microsecond=0)
    return None


def _parse_numeric(raw: str, now: datetime, order: str) -> datetime | None:
    m = re.fullmatch(r"(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})(?:\s+" + _TIME + r")?", raw.replace(",", "").strip())
    if not m:
        return None
    a, b, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
    year += 2000 if year < 100 else 0
    if order == "auto":
        # Data com AM/PM indica formato americano (mês/dia); caso contrário, dia/mês (Brasil).
        order = "mdy" if m.group("ampm") else "dmy"
        if order == "dmy" and b > 12 >= a:
            order = "mdy"
    day, month = (a, b) if order == "dmy" else (b, a)
    h, mi, s = _time_of(m)
    return datetime(year, month, day, h, mi, s)


def _parse_month_name(raw: str, now: datetime, order: str) -> datetime | None:
    text = _strip(raw)
    # "oct 6 2026 8:01 am" (inglês) ou "6 out 2026 08:01" (português)
    m = re.fullmatch(r"(?P<mon>[a-z]+)\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})(?:\s+" + _TIME + r")?", text) or re.fullmatch(
        r"(?P<day>\d{1,2})\s+(?P<mon>[a-z]+)\s+(?P<year>\d{4})(?:\s+" + _TIME + r")?", text
    )
    if not m or m.group("mon") not in _MONTHS:
        return None
    h, mi, s = _time_of(m)
    return datetime(int(m.group("year")), _MONTHS[m.group("mon")], int(m.group("day")), h, mi, s)


def _parse_time_only(raw: str, now: datetime, order: str) -> datetime | None:
    """'09:12:33' — o Zabbix omite a data de eventos do dia. Horário no futuro = ontem."""
    m = re.fullmatch(_TIME, raw.strip())
    if not m:
        return None
    h, mi, s = _time_of(m)
    value = now.replace(hour=h, minute=mi, second=s, microsecond=0)
    return value - timedelta(days=1) if value > now + timedelta(minutes=5) else value


def _parse_number(text: str) -> float | None:
    if "," in text and "." in text:
        # O último separador é o decimal: "1.234,5" (pt) ou "1,234.5" (en).
        decimal = "," if text.rfind(",") > text.rfind(".") else "."
        thousands = "." if decimal == "," else ","
        text = text.replace(thousands, "").replace(decimal, ".")
    else:
        text = text.replace(",", ".")
    try:
        return float(text)
    except ValueError:
        return None

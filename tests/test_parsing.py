from datetime import datetime

import pytest

from jervis.collectors.parsing import is_never, parse_datetime, parse_duration, parse_size, to_iso

NOW = datetime(2026, 10, 6, 12, 0)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("06/10/2026 09:00", datetime(2026, 10, 6, 9, 0)),
        ("06/10/2026", datetime(2026, 10, 6)),
        ("10/6/2026, 9:00 AM", datetime(2026, 10, 6, 9, 0)),
        ("10/6/2026 9:00:30 PM", datetime(2026, 10, 6, 21, 0, 30)),
        ("10/25/2026", datetime(2026, 10, 25)),  # mês/dia inferido: 25 não pode ser mês
        ("Oct 6, 2026 8:01 AM", datetime(2026, 10, 6, 8, 1)),
        ("Sep 30, 2026 12:40 PM", datetime(2026, 9, 30, 12, 40)),
        ("6 de out. de 2026 às 08:01", datetime(2026, 10, 6, 8, 1)),
        ("06 dez 2026", datetime(2026, 12, 6)),
        ("2026-10-06 09:00", datetime(2026, 10, 6, 9, 0)),
        ("há 2 horas", datetime(2026, 10, 6, 10, 0)),
        ("há 5 dias", datetime(2026, 10, 1, 12, 0)),
        ("3 days ago", datetime(2026, 10, 3, 12, 0)),
        ("an hour ago", datetime(2026, 10, 6, 11, 0)),
        ("Hoje, 09:15", datetime(2026, 10, 6, 9, 15)),
        ("Yesterday at 9:00 PM", datetime(2026, 10, 5, 21, 0)),
        ("agora", NOW),
    ],
)
def test_parse_datetime(text, expected):
    assert parse_datetime(text, NOW) == expected


@pytest.mark.parametrize("text", ["Nunca", "Never", "", None, "lixo", "31/02/2026", "—"])
def test_parse_datetime_unrecognized(text):
    assert parse_datetime(text, NOW) is None


def test_explicit_date_order():
    assert parse_datetime("06/10/2026", NOW, order="mdy") == datetime(2026, 6, 10)


def test_iso_with_timezone_is_converted_to_local():
    utc = parse_datetime("2026-10-06T12:00:00Z", NOW)
    assert to_iso(utc) == to_iso(datetime.fromisoformat("2026-10-06T12:00:00+00:00").astimezone().replace(tzinfo=None))


def test_is_never():
    assert is_never("Nunca") and is_never("Never") and not is_never("06/10/2026")


@pytest.mark.parametrize(
    "text, seconds",
    [("1 h 5 min", 3900), ("00:12:30", 750), ("12:30", 750), ("45 s", 45), ("2 horas 3 minutos", 7380),
     ("1.5 h", 5400), ("1d 2h", 93600), ("", None), ("rápido", None)],
)
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize(
    "text, size",
    [("1,5 GB", 1610612736), ("850 MB", 891289600), ("1.234,5 MB", 1294467072), ("1,234.5 MB", 1294467072),
     ("0 B", 0), ("3 TB", 3 * 1024**4), ("12 KiB", 12288), ("", None), ("muito", None)],
)
def test_parse_size(text, size):
    assert parse_size(text) == size

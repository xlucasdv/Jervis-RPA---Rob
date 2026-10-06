import logging

from jervis.security import MASK, RedactingFormatter, SecretStr, mask_username, redact


def test_secret_never_shown_in_str_or_repr():
    secret = SecretStr("p4ss-unica-1")
    assert "p4ss-unica-1" not in str(secret)
    assert "p4ss-unica-1" not in repr(secret)
    assert "p4ss-unica-1" not in f"{secret} {secret!r} {[secret]}"
    assert secret.reveal() == "p4ss-unica-1"


def test_redact_replaces_registered_secrets():
    SecretStr("abc-segredo-xyz")
    assert redact("falha com senha abc-segredo-xyz no login") == f"falha com senha {MASK} no login"


def test_formatter_redacts_messages_and_tracebacks():
    secret = SecretStr("tb-secreto-42")
    formatter = RedactingFormatter("%(message)s")
    try:
        raise ValueError(f"erro contendo {secret.reveal()}")
    except ValueError:
        import sys

        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "senha=%s", ("tb-secreto-42",), sys.exc_info())
    output = formatter.format(record)
    assert "tb-secreto-42" not in output
    assert MASK in output


def test_very_short_values_are_not_registered():
    SecretStr("ab")
    assert redact("tabela") == "tabela"


def test_mask_username():
    assert mask_username("joao.silva@empresa.com") == "jo***@empresa.com"
    assert mask_username("admin") == "ad***"

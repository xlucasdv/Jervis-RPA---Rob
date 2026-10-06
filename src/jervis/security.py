"""Proteção de segredos: valores mascarados e redação de logs/relatórios.

Todo segredo carregado pela aplicação é encapsulado em ``SecretStr``, que se
registra automaticamente. Qualquer texto que passe por ``redact`` (logs via
``RedactingFormatter``, relatórios, mensagens de erro) tem esses valores
substituídos por ``MASK``.
"""

from __future__ import annotations

import logging
import threading

MASK = "********"
# Valores mais curtos não são mascarados: trocar cada ocorrência de "ab" tornaria os
# logs ilegíveis, e senhas reais nunca são tão curtas.
MIN_SECRET_LENGTH = 4

_lock = threading.Lock()
_secrets: set[str] = set()


def register_secret(value: str) -> None:
    """Registra um valor para ser mascarado em toda saída da aplicação."""
    if value and len(value) >= MIN_SECRET_LENGTH:
        with _lock:
            _secrets.add(value)


def clear_registered_secrets() -> None:
    """Esvazia o registro de segredos (uso em testes)."""
    with _lock:
        _secrets.clear()


def redact(text: str) -> str:
    """Substitui todos os segredos registrados presentes em ``text`` por ``MASK``."""
    if not text:
        return text
    with _lock:
        # Mais longos primeiro, para que um segredo contido em outro não deixe sobras.
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, MASK)
    return text


class SecretStr:
    """String sensível: nunca aparece em ``str``/``repr``; use ``reveal()`` explicitamente."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value
        register_secret(value)

    def reveal(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __repr__(self) -> str:
        return f"SecretStr('{MASK}')"

    def __str__(self) -> str:
        return MASK


def mask_username(username: str) -> str:
    """Mascara parcialmente um usuário para logs (``jo***@empresa.com``)."""
    if "@" in username:
        local, domain = username.split("@", 1)
        return f"{local[:2]}***@{domain}"
    return f"{username[:2]}***"


class RedactingFormatter(logging.Formatter):
    """Formatter que aplica ``redact`` à linha final, incluindo tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))

"""Provedores de código MFA (autenticação adicional)."""

from __future__ import annotations

import binascii
import sys
import time
from typing import Callable, Protocol

import pyotp

from jervis.credentials import Credentials
from jervis.errors import MfaFailedError, MfaRequiredError


class MfaProvider(Protocol):
    def get_code(self, platform: str, credentials: Credentials) -> str: ...


class TotpProvider:
    """Gera o código a partir do segredo TOTP (o mesmo do Google/Microsoft Authenticator)."""

    def __init__(
        self,
        min_validity: float = 5.0,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.min_validity = min_validity
        self._clock = clock
        self._sleep = sleep

    def get_code(self, platform: str, credentials: Credentials) -> str:
        if not credentials.totp_secret:
            raise MfaRequiredError(
                platform,
                f"A plataforma usa MFA via TOTP, mas o segredo não foi cadastrado. "
                f"Use 'jervis credentials set {platform} --totp'.",
            )
        try:
            totp = pyotp.TOTP(normalize_totp_secret(credentials.totp_secret.reveal()))
            now = self._clock()
            remaining = totp.interval - (now % totp.interval)
            if remaining < self.min_validity:
                # Evita enviar um código que expira antes de a plataforma validá-lo.
                self._sleep(remaining + 0.5)
                now = self._clock()
            return totp.at(now)
        except (binascii.Error, ValueError) as exc:
            raise MfaFailedError(platform, "O segredo TOTP cadastrado é inválido (esperado base32).") from exc


class PromptProvider:
    """Solicita o código ao operador no terminal (SMS, e-mail, app sem segredo exportável)."""

    def __init__(self, input_func: Callable[[str], str] = input, interactive: bool | None = None):
        self._input = input_func
        self._interactive = interactive

    def get_code(self, platform: str, credentials: Credentials) -> str:
        interactive = sys.stdin.isatty() if self._interactive is None else self._interactive
        if not interactive:
            raise MfaRequiredError(
                platform,
                "A plataforma solicitou código MFA, mas a execução não é interativa. "
                "Configure 'mfa: totp' com o segredo do autenticador para execuções agendadas.",
            )
        code = self._input(f"Código de verificação para {platform}: ").strip()
        if not code:
            raise MfaFailedError(platform, "Nenhum código de verificação informado.")
        return code


def normalize_totp_secret(secret: str) -> str:
    return secret.replace(" ", "").replace("-", "").upper()


def is_valid_totp_secret(secret: str) -> bool:
    try:
        pyotp.TOTP(normalize_totp_secret(secret)).now()
        return True
    except (binascii.Error, ValueError):
        return False


def build_mfa_provider(method: str) -> MfaProvider | None:
    if method == "totp":
        return TotpProvider()
    if method == "prompt":
        return PromptProvider()
    return None

"""Credenciais das plataformas, sem nunca tocar o código-fonte ou o arquivo de configuração.

Ordem de busca:
  1. Variáveis de ambiente ``JERVIS_<PLATAFORMA>_USERNAME`` / ``_PASSWORD`` / ``_TOTP_SECRET``
     (indicado para execução agendada/CI, injetadas por um cofre externo);
  2. Cofre do sistema operacional via ``keyring``
     (Windows Credential Manager, macOS Keychain, Secret Service no Linux).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Mapping

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from jervis.errors import CredentialError, CredentialsNotFoundError
from jervis.security import SecretStr

SERVICE_NAME = "jervis3000"


@dataclass(frozen=True, eq=False)
class Credentials:
    username: str
    password: SecretStr
    totp_secret: SecretStr | None = None


@dataclass(frozen=True)
class CredentialStatus:
    source: str | None  # "env", "keyring" ou None
    has_totp: bool = False

    @property
    def configured(self) -> bool:
        return self.source is not None


def service_for(environment: str | None) -> str:
    """Cofre separado por ambiente: credenciais de homologação nunca são usadas em produção."""
    return f"{SERVICE_NAME}-{environment}" if environment else SERVICE_NAME


def env_prefix(platform: str) -> str:
    return "JERVIS_" + re.sub(r"[^A-Z0-9]", "_", platform.upper()) + "_"


class CredentialStore:
    def __init__(self, service: str = SERVICE_NAME, environ: Mapping[str, str] | None = None):
        self.service = service
        self.environ = os.environ if environ is None else environ

    @staticmethod
    def backend_name() -> str:
        return type(keyring.get_keyring()).__name__

    def get(self, platform: str) -> Credentials:
        creds = self._from_env(platform) or self._from_keyring(platform)
        if creds is None:
            prefix = env_prefix(platform)
            raise CredentialsNotFoundError(
                f"Nenhuma credencial cadastrada para '{platform}'. "
                f"Use 'jervis credentials set {platform}' ou defina {prefix}USERNAME e {prefix}PASSWORD."
            )
        return creds

    def status(self, platform: str) -> CredentialStatus:
        try:
            creds = self._from_env(platform)
            source = "env"
            if creds is None:
                creds, source = self._from_keyring(platform), "keyring"
        except CredentialError:
            return CredentialStatus(source=None)
        if creds is None:
            return CredentialStatus(source=None)
        return CredentialStatus(source=source, has_totp=bool(creds.totp_secret))

    def set(self, platform: str, username: str, password: str, totp_secret: str | None = None) -> None:
        if not username or not password:
            raise CredentialError("Usuário e senha são obrigatórios.")
        try:
            keyring.set_password(self.service, self._key(platform, "username"), username)
            keyring.set_password(self.service, self._key(platform, "password"), password)
            if totp_secret:
                keyring.set_password(self.service, self._key(platform, "totp_secret"), totp_secret)
            else:
                self._delete_quietly(platform, "totp_secret")
        except KeyringError as exc:
            raise CredentialError(self._keyring_failure_message(platform, exc)) from exc

    def delete(self, platform: str) -> bool:
        """Remove as credenciais do cofre. Retorna False se não havia nada cadastrado."""
        try:
            removed = [self._delete_quietly(platform, field) for field in ("username", "password", "totp_secret")]
        except KeyringError as exc:
            raise CredentialError(self._keyring_failure_message(platform, exc)) from exc
        return any(removed)

    def get_secret(self, key: str) -> str | None:
        """Segredo avulso (ex.: senha do SMTP de notificação)."""
        try:
            return keyring.get_password(self.service, key)
        except KeyringError as exc:
            raise CredentialError(self._keyring_failure_message(key, exc)) from exc

    def set_secret(self, key: str, value: str) -> None:
        try:
            keyring.set_password(self.service, key, value)
        except KeyringError as exc:
            raise CredentialError(self._keyring_failure_message(key, exc)) from exc

    def delete_secret(self, key: str) -> bool:
        try:
            keyring.delete_password(self.service, key)
            return True
        except PasswordDeleteError:
            return False

    def _from_env(self, platform: str) -> Credentials | None:
        prefix = env_prefix(platform)
        username = self.environ.get(prefix + "USERNAME")
        password = self.environ.get(prefix + "PASSWORD")
        if not username and not password:
            return None
        if not username or not password:
            raise CredentialError(f"Defina {prefix}USERNAME e {prefix}PASSWORD juntas (apenas uma foi encontrada).")
        totp = self.environ.get(prefix + "TOTP_SECRET")
        return Credentials(username, SecretStr(password), SecretStr(totp) if totp else None)

    def _from_keyring(self, platform: str) -> Credentials | None:
        try:
            username = keyring.get_password(self.service, self._key(platform, "username"))
            password = keyring.get_password(self.service, self._key(platform, "password"))
            totp = keyring.get_password(self.service, self._key(platform, "totp_secret"))
        except KeyringError as exc:
            raise CredentialError(self._keyring_failure_message(platform, exc)) from exc
        if not username or not password:
            return None
        return Credentials(username, SecretStr(password), SecretStr(totp) if totp else None)

    def _delete_quietly(self, platform: str, field: str) -> bool:
        try:
            keyring.delete_password(self.service, self._key(platform, field))
            return True
        except PasswordDeleteError:
            return False

    @staticmethod
    def _key(platform: str, field: str) -> str:
        return f"{platform}:{field}"

    @staticmethod
    def _keyring_failure_message(platform: str, exc: Exception) -> str:
        prefix = env_prefix(platform)
        return (
            f"Cofre de senhas do sistema indisponível ({type(exc).__name__}). "
            f"Alternativa: defina {prefix}USERNAME e {prefix}PASSWORD como variáveis de ambiente."
        )

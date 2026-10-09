"""Criptografia da chave MFA guardada em customer_services.mfa_secret_encrypted.

Usa Fernet (AES-128-CBC + HMAC-SHA256). A chave de criptografia fica fora do banco: no cofre do sistema
(jervis db generate-key) ou na variável JERVIS_MFA_ENCRYPTION_KEY. Quem lê só o banco, ou um backup dele,
não consegue gerar os códigos MFA.
"""

from __future__ import annotations

import os
from typing import Mapping

from cryptography.fernet import Fernet, InvalidToken

from jervis.credentials import CredentialStore
from jervis.errors import JervisError
from jervis.security import SecretStr

ENV_KEY = "JERVIS_MFA_ENCRYPTION_KEY"
VAULT_KEY = "banco:chave_mfa"


class EncryptionKeyError(JervisError):
    """Chave de criptografia ausente, inválida ou diferente da usada para criptografar."""


def new_key() -> str:
    return Fernet.generate_key().decode("ascii")


def load_key(store: CredentialStore, environ: Mapping[str, str] | None = None) -> str:
    environ = os.environ if environ is None else environ
    key = environ.get(ENV_KEY) or store.get_secret(VAULT_KEY)
    if not key:
        raise EncryptionKeyError(
            "Chave de criptografia da chave MFA não encontrada. Gere com 'jervis db generate-key' "
            f"(fica no cofre do sistema) ou defina {ENV_KEY}."
        )
    return key


def _fernet(key: str) -> Fernet:
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EncryptionKeyError("Chave de criptografia inválida (esperado o formato gerado por 'jervis db generate-key').") from exc


def encrypt_secret(secret: str | SecretStr, key: str) -> str:
    value = secret.reveal() if isinstance(secret, SecretStr) else secret
    return _fernet(key).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str, key: str) -> SecretStr:
    try:
        return SecretStr(_fernet(key).decrypt(token.encode("ascii")).decode("utf-8"))
    except InvalidToken as exc:
        raise EncryptionKeyError(
            "Não foi possível descriptografar a chave MFA: a chave de criptografia é diferente da usada para gravá-la."
        ) from exc

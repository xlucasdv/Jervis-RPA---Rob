"""Senhas e app autenticador das contas da interface.

Senhas: scrypt (biblioteca padrão) com sal por conta; só o hash vai para o banco. App autenticador: TOTP de 6
dígitos (Microsoft Authenticator, Google Authenticator...), chave criptografada no banco e o mesmo código aceito
uma vez só.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

import pyotp

N, R, P, DKLEN = 2 ** 15, 8, 1, 32  # ~32 MB e algumas dezenas de ms por verificação
MIN_LENGTH = 12
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # sem 0/o, 1/l/i: a senha temporária é ditada ou copiada
_COMMON = {"senha123456", "123456789012", "contego12345", "jervis300012", "qwertyuiop12", "password1234"}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=R, p=P, dklen=DKLEN, maxmem=64 * 1024 * 1024)
    return "scrypt${}${}${}${}${}".format(N, R, P, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str | None) -> bool:
    try:
        scheme, n, r, p, salt, digest = (stored or "").split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(expected), maxmem=64 * 1024 * 1024)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Conta inexistente também gasta o tempo de uma verificação: o tempo de resposta não revela quem tem conta
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def temporary_password() -> str:
    """Ex.: kq7m-x2pr-9fhw-t4za (80 bits). Vale só até o primeiro login."""
    chars = "".join(secrets.choice(_ALPHABET) for _ in range(16))
    return "-".join(chars[i:i + 4] for i in range(0, 16, 4))


def password_problem(password: str, email: str) -> str | None:
    """Motivo para recusar a nova senha, ou None se está boa."""
    if len(password) < MIN_LENGTH:
        return f"Use ao menos {MIN_LENGTH} caracteres (uma frase curta funciona bem)."
    if len(password) > 128:
        return "Use no máximo 128 caracteres."
    lowered = password.lower()
    local = email.split("@")[0].lower()
    if len(local) >= 4 and local in lowered:
        return "A senha não pode conter o seu e-mail."
    if len(set(password)) < 5 or lowered in _COMMON:
        return "Essa senha é fácil de adivinhar. Escolha outra."
    return None


def new_mfa_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Jervis3000")


def qr_svg(uri: str) -> str:
    """QR code como data URI (a página não carrega nada de fora)."""
    import segno

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2)


def verify_code(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Passo de tempo do código, se ele vale (30 s de tolerância) e ainda não foi usado; senão None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // 30)
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * 30), code) and (last_step is None or step > last_step):
            return step
    return None

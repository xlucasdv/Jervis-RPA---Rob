import pyotp
import pytest

from jervis.auth.mfa import PromptProvider, TotpProvider, is_valid_totp_secret
from jervis.credentials import Credentials
from jervis.errors import MfaFailedError, MfaRequiredError
from jervis.security import SecretStr

SECRET = "JBSWY3DPEHPK3PXP"


def creds(totp=None):
    return Credentials("op", SecretStr("x"), SecretStr(totp) if totp else None)


def test_totp_generates_current_code():
    provider = TotpProvider(clock=lambda: 1_000_000_010.0)
    assert provider.get_code("sophos", creds(SECRET)) == pyotp.TOTP(SECRET).at(1_000_000_010)


def test_totp_waits_for_next_window_when_code_is_about_to_expire():
    now = [1_000_000_018.0]  # 2s restantes na janela de 30s
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    code = TotpProvider(clock=lambda: now[0], sleep=sleep).get_code("sophos", creds(SECRET))
    assert slept and code == pyotp.TOTP(SECRET).at(now[0])
    assert code != pyotp.TOTP(SECRET).at(1_000_000_018)


def test_totp_accepts_spaced_lowercase_secret():
    code = TotpProvider(clock=lambda: 1_000_000_010.0).get_code("s", creds("jbsw y3dp ehpk 3pxp"))
    assert code == pyotp.TOTP(SECRET).at(1_000_000_010)


def test_totp_without_secret_requires_configuration():
    with pytest.raises(MfaRequiredError, match="--totp"):
        TotpProvider().get_code("sophos", creds())


def test_totp_invalid_secret():
    with pytest.raises(MfaFailedError, match="inválido"):
        TotpProvider().get_code("sophos", creds("não-é-base32!"))
    assert not is_valid_totp_secret("não-é-base32!")
    assert is_valid_totp_secret(SECRET)


def test_prompt_requires_interactive_terminal():
    with pytest.raises(MfaRequiredError, match="não é interativa"):
        PromptProvider(interactive=False).get_code("acronis", creds())


def test_prompt_reads_code():
    assert PromptProvider(input_func=lambda _: " 654321 ", interactive=True).get_code("acronis", creds()) == "654321"

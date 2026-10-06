"""Testes de ponta a ponta do login com um navegador real contra páginas falsas locais."""

import pytest

from jervis.auth.authenticator import FormLoginAuthenticator
from jervis.auth.mfa import PromptProvider
from jervis.auth.profiles import PROFILES, LoginProfile
from jervis.config import PlatformConfig
from jervis.credentials import Credentials
from jervis.errors import AccessDeniedError, LoginTimeoutError, MfaFailedError, MfaRequiredError
from jervis.security import SecretStr

pytestmark = pytest.mark.browser

GOOD = Credentials("operador", SecretStr("S3nh@-forte"))

# Perfil da Acronis ajustado à página falsa (sucesso pelo menu lateral, não pela URL).
TWO_STEP = PROFILES["acronis"].with_overrides({"success": ["aside.sidebar"]})


def authenticator(url, credentials=GOOD, profile: LoginProfile = PROFILES["zabbix"], mfa=None, timeout=5):
    platform = PlatformConfig(name="teste", kind="zabbix", url=url, enabled=True)
    return FormLoginAuthenticator(platform, profile, credentials, mfa=mfa, timeout=timeout, poll_interval=0.2)


@pytest.fixture(autouse=True)
def fresh_page(driver):
    driver.delete_all_cookies()
    yield


def test_single_step_login_success(driver, site_url):
    result = authenticator(f"{site_url}/login.html").login(driver)
    assert result.url.endswith("/dashboard.html")
    assert not result.used_mfa and not result.reused_session


def test_wrong_password_is_access_denied_with_platform_message(driver, site_url):
    bad = Credentials("operador", SecretStr("errada-123"))
    with pytest.raises(AccessDeniedError) as exc:
        authenticator(f"{site_url}/login.html", credentials=bad).login(driver)
    assert "Usuário ou senha incorretos." in str(exc.value)
    assert "errada-123" not in str(exc.value)


def test_mfa_success_with_code(driver, site_url):
    mfa = PromptProvider(input_func=lambda _: "123456", interactive=True)
    result = authenticator(f"{site_url}/login.html?mfa=1", mfa=mfa).login(driver)
    assert result.used_mfa
    assert result.url.endswith("/dashboard.html")


def test_mfa_wrong_code(driver, site_url):
    mfa = PromptProvider(input_func=lambda _: "000000", interactive=True)
    with pytest.raises(MfaFailedError, match="Código de verificação inválido"):
        authenticator(f"{site_url}/login.html?mfa=1", mfa=mfa).login(driver)


def test_mfa_requested_but_not_configured(driver, site_url):
    with pytest.raises(MfaRequiredError, match="nenhum método"):
        authenticator(f"{site_url}/login.html?mfa=1").login(driver)


def test_two_step_login_success(driver, site_url):
    creds = Credentials("operador@empresa.com", SecretStr("S3nh@-forte"))
    result = authenticator(f"{site_url}/two_step.html", credentials=creds, profile=TWO_STEP).login(driver)
    assert result.url.endswith("/dashboard.html")


def test_two_step_unknown_user_is_access_denied(driver, site_url):
    creds = Credentials("ninguem@empresa.com", SecretStr("S3nh@-forte"))
    with pytest.raises(AccessDeniedError, match="Conta não encontrada"):
        authenticator(f"{site_url}/two_step.html", credentials=creds, profile=TWO_STEP).login(driver)


def test_two_step_wrong_password(driver, site_url):
    creds = Credentials("operador@empresa.com", SecretStr("errada"))
    with pytest.raises(AccessDeniedError, match="Senha incorreta"):
        authenticator(f"{site_url}/two_step.html", credentials=creds, profile=TWO_STEP).login(driver)


def test_already_authenticated_session_is_reused(driver, site_url):
    result = authenticator(f"{site_url}/dashboard.html").login(driver)
    assert result.reused_session


def test_page_without_login_form_times_out_with_guidance(driver, site_url):
    with pytest.raises(LoginTimeoutError, match="seletores"):
        authenticator(f"{site_url}/blank.html", timeout=1).login(driver)

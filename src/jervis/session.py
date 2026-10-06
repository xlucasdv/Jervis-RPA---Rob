"""Abertura de sessões autenticadas nas plataformas (ponto de entrada para a coleta)."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Callable, Iterator

from selenium.webdriver.remote.webdriver import WebDriver

from jervis.auth.authenticator import FormLoginAuthenticator, LoginResult
from jervis.auth.mfa import MfaProvider, build_mfa_provider
from jervis.auth.profiles import PROFILES
from jervis.browser import create_driver
from jervis.config import PlatformConfig, Settings
from jervis.credentials import CredentialStore
from jervis.diagnostics import save_screenshot
from jervis.errors import ConfigError, JervisError

log = logging.getLogger(__name__)

DriverFactory = Callable[[Settings], WebDriver]


def build_authenticator(
    platform: PlatformConfig,
    settings: Settings,
    store: CredentialStore,
    mfa: MfaProvider | None = None,
) -> FormLoginAuthenticator:
    if not platform.url:
        raise ConfigError(f"A plataforma '{platform.name}' não tem URL cadastrada.")
    profile = PROFILES[platform.kind].with_overrides(platform.selectors)
    return FormLoginAuthenticator(
        platform=platform,
        profile=profile,
        credentials=store.get(platform.name),
        mfa=mfa or build_mfa_provider(platform.mfa),
        timeout=platform.login_timeout or settings.login_timeout,
    )


@contextmanager
def platform_session(
    platform: PlatformConfig,
    settings: Settings,
    store: CredentialStore,
    driver_factory: DriverFactory = create_driver,
) -> Iterator[tuple[WebDriver, LoginResult]]:
    """Abre o navegador, autentica e entrega o driver logado; fecha o navegador ao sair.

    Uso pelas etapas de coleta::

        with platform_session(platform, settings, store) as (driver, login):
            ...
    """
    if not platform.enabled:
        raise ConfigError(f"A plataforma '{platform.name}' está desativada. Use 'jervis platforms enable {platform.name}'.")
    # Validado antes de abrir o navegador, para falhar rápido se faltar credencial.
    authenticator = build_authenticator(platform, settings, store)
    driver = driver_factory(settings)
    try:
        try:
            result = authenticator.login(driver)
        except JervisError:
            save_screenshot(driver, settings, platform.name, "login")
            raise
        yield driver, result
    finally:
        driver.quit()


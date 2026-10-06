"""Login automatizado via Selenium, guiado por um ``LoginProfile``.

O fluxo é adaptativo e cobre as variações das três plataformas:
  * usuário e senha na mesma tela (Zabbix, Sophos ID);
  * usuário → "Avançar" → senha (Acronis);
  * etapa adicional de MFA, quando a plataforma a apresenta;
  * sessão já autenticada (nada a fazer).

Após cada ação, a página é observada até que um estado reconhecível apareça
(erro, MFA, campo de senha, sucesso) ou o tempo limite se esgote.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Callable

from selenium.common.exceptions import (
    ElementClickInterceptedException,
    InvalidSessionIdException,
    NoSuchWindowException,
    WebDriverException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

from jervis.auth.mfa import MfaProvider
from jervis.auth.profiles import LoginProfile
from jervis.credentials import Credentials
from jervis.errors import (
    AccessDeniedError,
    LoginTimeoutError,
    MfaFailedError,
    MfaRequiredError,
    PlatformUnavailableError,
)
from jervis.security import mask_username, redact

if TYPE_CHECKING:
    from jervis.config import PlatformConfig

log = logging.getLogger(__name__)


class State(Enum):
    ERROR = auto()
    MFA = auto()
    PASSWORD = auto()
    USERNAME = auto()
    SUCCESS = auto()


# Ordem de prioridade na detecção: um erro visível prevalece sobre qualquer outro sinal.
_DETECTION_ORDER = (State.ERROR, State.MFA, State.PASSWORD, State.USERNAME, State.SUCCESS)


@dataclass(frozen=True)
class LoginResult:
    platform: str
    url: str
    elapsed: float
    used_mfa: bool = False
    reused_session: bool = False


class FormLoginAuthenticator:
    def __init__(
        self,
        platform: PlatformConfig,
        profile: LoginProfile,
        credentials: Credentials,
        mfa: MfaProvider | None = None,
        timeout: float = 30.0,
        poll_interval: float = 0.5,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.platform = platform
        self.profile = profile
        self.credentials = credentials
        self.mfa = mfa
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._clock = clock
        self._sleep = sleep
        self._success_url = [re.compile(p) for p in profile.success_url]

    @property
    def name(self) -> str:
        return self.platform.name

    def login(self, driver: WebDriver) -> LoginResult:
        start = self._clock()
        log.info("[%s] Acessando %s", self.name, self.platform.url)
        try:
            driver.get(self.platform.url)
        except WebDriverException as exc:
            raise PlatformUnavailableError(
                f"[{self.name}] Não foi possível abrir {self.platform.url}: {(exc.msg or str(exc)).strip()}"
            ) from exc

        if self._wait_for(driver, {State.USERNAME, State.SUCCESS}, "a tela de login") is State.SUCCESS:
            log.info("[%s] Sessão já autenticada", self.name)
            return self._result(driver, start, reused_session=True)

        user_field = self._find_visible(driver, self.profile.username)
        self._type(user_field, self.credentials.username, "usuário")
        log.info("[%s] Usuário informado: %s", self.name, mask_username(self.credentials.username))

        if self._find_visible(driver, self.profile.password) is None:
            log.info("[%s] Login em duas etapas: avançando para a senha", self.name)
            self._click(driver, self.profile.next or self.profile.submit, fallback=user_field)
            if self._wait_for(driver, {State.PASSWORD, State.ERROR}, "o campo de senha") is State.ERROR:
                self._raise_access_denied(driver)

        password_field = self._find_visible(driver, self.profile.password)
        self._type(password_field, self.credentials.password.reveal(), "senha")
        self._click(driver, self.profile.submit, fallback=password_field)
        log.info("[%s] Credenciais enviadas; aguardando resposta", self.name)

        state = self._wait_for(driver, {State.SUCCESS, State.ERROR, State.MFA}, "a resposta do login")
        if state is State.ERROR:
            self._raise_access_denied(driver)

        used_mfa = state is State.MFA
        if used_mfa:
            self._complete_mfa(driver)

        log.info("[%s] Login realizado com sucesso", self.name)
        return self._result(driver, start, used_mfa=used_mfa)

    def _complete_mfa(self, driver: WebDriver) -> None:
        if self.mfa is None:
            raise MfaRequiredError(
                self.name,
                "A plataforma solicitou autenticação adicional (MFA), mas nenhum método está configurado. "
                "Defina 'mfa: totp' ou 'mfa: prompt' para esta plataforma.",
            )
        log.info("[%s] Autenticação adicional (MFA) solicitada", self.name)
        code = self.mfa.get_code(self.name, self.credentials)
        field = self._find_visible(driver, self.profile.mfa_input)
        self._type(field, code, "código MFA")
        self._click(driver, self.profile.mfa_submit, fallback=field)
        try:
            state = self._wait_for(driver, {State.SUCCESS, State.ERROR}, "a validação do código MFA")
        except LoginTimeoutError as exc:
            raise MfaFailedError(self.name, f"O código MFA não foi aceito. {exc.message}") from exc
        if state is State.ERROR:
            raise MfaFailedError(self.name, f"Código MFA recusado pela plataforma: \"{self._error_message(driver)}\"")

    # --- observação da página -------------------------------------------------

    def _wait_for(self, driver: WebDriver, wanted: set[State], what: str) -> State:
        deadline = self._clock() + self.timeout
        while True:
            state = self._detect(driver, wanted)
            if state is not None:
                return state
            if self._clock() >= deadline:
                raise LoginTimeoutError(
                    self.name,
                    f"Tempo esgotado ({self.timeout:.0f}s) aguardando {what} em {self._current_url(driver)}. "
                    "Verifique a URL, a disponibilidade da plataforma e os seletores configurados.",
                )
            self._sleep(self.poll_interval)

    def _detect(self, driver: WebDriver, wanted: set[State]) -> State | None:
        checks = {
            State.ERROR: lambda: bool(self._error_message(driver)),
            State.MFA: lambda: self._find_visible(driver, self.profile.mfa_input) is not None,
            State.PASSWORD: lambda: self._find_visible(driver, self.profile.password) is not None,
            State.USERNAME: lambda: self._find_visible(driver, self.profile.username) is not None,
            State.SUCCESS: lambda: self._is_logged_in(driver),
        }
        for state in _DETECTION_ORDER:
            if state not in wanted:
                continue
            try:
                if checks[state]():
                    return state
            except (InvalidSessionIdException, NoSuchWindowException):
                raise
            except WebDriverException:
                # Página em transição (navegação, elemento obsoleto): tenta de novo no próximo ciclo.
                continue
        return None

    def _is_logged_in(self, driver: WebDriver) -> bool:
        if self._find_visible(driver, self.profile.password) is not None:
            return False
        if self._find_visible(driver, self.profile.success) is not None:
            return True
        url = driver.current_url
        return any(p.search(url) for p in self._success_url)

    def _error_message(self, driver: WebDriver) -> str:
        for selector in self.profile.error:
            for element in driver.find_elements(By.CSS_SELECTOR, selector):
                if element.is_displayed():
                    text = " ".join(element.text.split())
                    if text:
                        return redact(text[:300])
        return ""

    # --- interação ---------------------------------------------------------------

    @staticmethod
    def _find_visible(driver: WebDriver, selectors: tuple[str, ...]) -> WebElement | None:
        for selector in selectors:
            for element in driver.find_elements(By.CSS_SELECTOR, selector):
                if element.is_displayed():
                    return element
        return None

    def _type(self, element: WebElement | None, text: str, label: str) -> None:
        if element is None:
            # Estado detectado, mas o elemento sumiu entre a detecção e a ação.
            raise LoginTimeoutError(
                self.name, f"O campo de {label} não foi encontrado na página. Verifique os seletores configurados."
            )
        element.clear()
        element.send_keys(text)

    def _click(self, driver: WebDriver, selectors: tuple[str, ...], fallback: WebElement) -> None:
        button = next(
            (
                el
                for sel in selectors
                for el in driver.find_elements(By.CSS_SELECTOR, sel)
                if el.is_displayed() and el.is_enabled()
            ),
            None,
        )
        if button is None:
            fallback.send_keys(Keys.ENTER)
            return
        try:
            button.click()
        except ElementClickInterceptedException:
            driver.execute_script("arguments[0].click();", button)

    def _raise_access_denied(self, driver: WebDriver) -> None:
        message = self._error_message(driver)
        raise AccessDeniedError(
            self.name,
            f"Acesso negado pela plataforma: \"{message}\". "
            f"Confira usuário e senha com 'jervis credentials set {self.name}'.",
        )

    @staticmethod
    def _current_url(driver: WebDriver) -> str:
        try:
            return driver.current_url
        except WebDriverException:
            return "(URL indisponível)"

    def _result(self, driver: WebDriver, start: float, **kwargs) -> LoginResult:
        return LoginResult(
            platform=self.name, url=self._current_url(driver), elapsed=self._clock() - start, **kwargs
        )

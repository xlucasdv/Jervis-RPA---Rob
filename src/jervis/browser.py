"""Criação do WebDriver.

Por padrão o Selenium Manager baixa o driver compatível automaticamente. Em
máquinas onde isso não é possível (sem internet, ou com política de controle
de aplicativos bloqueando o ``selenium-manager.exe``), ``settings.driver_path``
aponta para um driver já aprovado.
"""

from __future__ import annotations

from pathlib import Path

from selenium import webdriver
from selenium.common.exceptions import NoSuchDriverException, WebDriverException
from selenium.webdriver.remote.webdriver import WebDriver

from jervis.config import Settings
from jervis.errors import BrowserError

# Evita que o navegador ofereça salvar as senhas digitadas pela automação.
_CHROMIUM_PREFS = {"credentials_enable_service": False, "profile.password_manager_enabled": False}

_DRIVER_HINT = (
    " Não foi possível obter o driver automaticamente (sem internet ou bloqueado por política de "
    "segurança). Baixe o driver compatível com a versão do navegador e informe-o em settings.driver_path."
)


def create_driver(settings: Settings, headless: bool | None = None) -> WebDriver:
    headless = settings.headless if headless is None else headless
    driver_path = settings.driver_path or None
    if driver_path and not Path(driver_path).is_file():
        raise BrowserError(f"Driver não encontrado em settings.driver_path: {driver_path}")
    try:
        if settings.browser == "firefox":
            options = webdriver.FirefoxOptions()
            options.add_argument("-private")
            if headless:
                options.add_argument("-headless")
            driver = webdriver.Firefox(options=options, service=webdriver.FirefoxService(executable_path=driver_path))
        elif settings.browser == "edge":
            options = _chromium_options(webdriver.EdgeOptions(), "--inprivate", headless)
            driver = webdriver.Edge(options=options, service=webdriver.EdgeService(executable_path=driver_path))
        else:
            options = _chromium_options(webdriver.ChromeOptions(), "--incognito", headless)
            driver = webdriver.Chrome(options=options, service=webdriver.ChromeService(executable_path=driver_path))
    except NoSuchDriverException as exc:
        raise BrowserError(f"Não foi possível iniciar o navegador '{settings.browser}'.{_DRIVER_HINT}") from exc
    except WebDriverException as exc:
        raise BrowserError(
            f"Não foi possível iniciar o navegador '{settings.browser}': {(exc.msg or str(exc)).strip()}"
        ) from exc
    driver.set_page_load_timeout(settings.page_load_timeout)
    return driver


def _chromium_options(options, private_flag: str, headless: bool):
    options.add_argument(private_flag)
    options.add_argument("--window-size=1920,1080")
    options.add_experimental_option("prefs", _CHROMIUM_PREFS)
    if headless:
        options.add_argument("--headless=new")
    return options

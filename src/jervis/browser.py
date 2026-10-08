"""Criação do WebDriver.

Por padrão o Selenium Manager baixa o driver compatível automaticamente. Em
máquinas onde isso não é possível (sem internet, ou com política de controle
de aplicativos bloqueando o ``selenium-manager.exe``), ``settings.driver_path``
aponta para um driver já aprovado.
"""

from __future__ import annotations

from pathlib import Path

from selenium import webdriver
from selenium.common.exceptions import NoSuchDriverException, SessionNotCreatedException, WebDriverException
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
    profile = profile_dir(settings)
    driver_path = settings.driver_path or None
    if driver_path and not Path(driver_path).is_file():
        raise BrowserError(f"Driver não encontrado em settings.driver_path: {driver_path}")
    if driver_path:
        # Caminho absoluto: o Windows não executa um relativo escrito com "/" (drivers/msedgedriver.exe).
        driver_path = str(Path(driver_path).resolve())
    try:
        if settings.browser == "firefox":
            options = webdriver.FirefoxOptions()
            if profile is None:
                options.add_argument("-private")
            else:
                options.add_argument("-profile")
                options.add_argument(str(profile))
            if headless:
                options.add_argument("-headless")
            driver = webdriver.Firefox(options=options, service=webdriver.FirefoxService(executable_path=driver_path))
        elif settings.browser == "edge":
            options = _chromium_options(webdriver.EdgeOptions(), "--inprivate", headless, profile)
            driver = webdriver.Edge(options=options, service=webdriver.EdgeService(executable_path=driver_path))
        else:
            options = _chromium_options(webdriver.ChromeOptions(), "--incognito", headless, profile)
            driver = webdriver.Chrome(options=options, service=webdriver.ChromeService(executable_path=driver_path))
    except SessionNotCreatedException as exc:
        if profile is not None and "user data directory is already in use" in (exc.msg or str(exc)):
            raise BrowserError(f"O perfil do navegador ({profile}) já está em uso por outra janela aberta pela "
                               "ferramenta. Aguarde a outra execução terminar ou feche essa janela.") from exc
        raise BrowserError(f"Não foi possível iniciar o navegador '{settings.browser}': {(exc.msg or str(exc)).strip()}") from exc
    except NoSuchDriverException as exc:
        raise BrowserError(f"Não foi possível iniciar o navegador '{settings.browser}'.{_DRIVER_HINT}") from exc
    except WebDriverException as exc:
        raise BrowserError(
            f"Não foi possível iniciar o navegador '{settings.browser}': {(exc.msg or str(exc)).strip()}"
        ) from exc
    driver.set_page_load_timeout(settings.page_load_timeout)
    return driver


def profile_dir(settings: Settings) -> Path | None:
    """Pasta do perfil próprio (criada se não existir); None = janela anônima."""
    if not settings.browser_profile.strip():
        return None
    path = Path(settings.browser_profile).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _chromium_options(options, private_flag: str, headless: bool, profile: Path | None = None):
    if profile is None:
        options.add_argument(private_flag)
    else:
        options.add_argument(f"--user-data-dir={profile}")
    options.add_argument("--window-size=1920,1080")
    options.add_experimental_option("prefs", _CHROMIUM_PREFS)
    if headless:
        options.add_argument("--headless=new")
    return options

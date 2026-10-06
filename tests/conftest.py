from __future__ import annotations

import functools
import http.server
import os
import threading
from pathlib import Path

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

SITE_DIR = Path(__file__).parent / "fixtures" / "site"
# Driver aprovado para máquinas onde o Selenium Manager é bloqueado (lido antes de o
# fixture memory_keyring limpar as variáveis JERVIS_*).
TEST_DRIVER_PATH = os.environ.get("JERVIS_TEST_DRIVER_PATH", "")


class MemoryKeyring(KeyringBackend):
    """Cofre em memória: os testes nunca tocam o cofre real do sistema."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.data: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        if self.data.pop((service, username), None) is None:
            raise PasswordDeleteError(username)


@pytest.fixture(autouse=True)
def isolated_secrets():
    from jervis.security import clear_registered_secrets

    clear_registered_secrets()
    yield
    clear_registered_secrets()


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch):
    backend = MemoryKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    for var in [v for v in os.environ if v.startswith("JERVIS_")]:
        monkeypatch.delenv(var)
    yield backend
    keyring.set_keyring(previous)


@pytest.fixture(scope="session")
def site_url():
    """Servidor HTTP local com páginas de login falsas."""
    handler = functools.partial(_QuietHandler, directory=str(SITE_DIR))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def driver():
    from jervis.browser import create_driver
    from jervis.config import Settings
    from jervis.errors import BrowserError

    try:
        drv = create_driver(Settings(browser="edge", driver_path=TEST_DRIVER_PATH, headless=True, page_load_timeout=15))
    except BrowserError as exc:
        pytest.skip(f"Navegador indisponível: {exc}")
    yield drv
    drv.quit()


@pytest.fixture
def driver_factory(driver):
    """Fábrica de navegadores novos (para testes que passam por platform_session, que fecha o navegador)."""
    from jervis.browser import create_driver

    def factory(settings):
        settings.driver_path = TEST_DRIVER_PATH
        settings.headless = True
        return create_driver(settings)

    return factory


@pytest.fixture(scope="session")
def test_driver_path():
    return TEST_DRIVER_PATH

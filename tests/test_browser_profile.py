"""Janela anônima (padrão) ou perfil próprio do navegador (settings.browser_profile)."""

import pytest
from selenium import webdriver

from jervis import cli
from jervis.browser import _chromium_options, create_driver, profile_dir
from jervis.config import Settings


def test_default_is_private_window():
    assert profile_dir(Settings()) is None
    options = _chromium_options(webdriver.EdgeOptions(), "--inprivate", headless=True)
    assert "--inprivate" in options.arguments
    assert not any(a.startswith("--user-data-dir") for a in options.arguments)


def test_profile_folder_gives_normal_window(tmp_path):
    profile = profile_dir(Settings(browser_profile=str(tmp_path / "perfil")))
    assert profile.is_dir()
    options = _chromium_options(webdriver.EdgeOptions(), "--inprivate", headless=True, profile=profile)
    assert "--inprivate" not in options.arguments
    assert f"--user-data-dir={profile}" in options.arguments


def test_invalid_profile_value(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    path = tmp_path / "platforms.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace('browser_profile: ""', "browser_profile: 123"), encoding="utf-8")
    assert cli.main(["-c", "platforms.yaml", "platforms", "list"]) == 1


@pytest.mark.browser
def test_profile_keeps_cookies_between_runs(tmp_path, site_url, test_driver_path):
    if not test_driver_path:
        pytest.skip("defina JERVIS_TEST_DRIVER_PATH")
    settings = Settings(driver_path=test_driver_path, headless=True, browser_profile=str(tmp_path / "perfil"))
    first = create_driver(settings)
    try:
        first.get(f"{site_url}/blank.html")
        first.execute_script("document.cookie = 'sessao=abc; max-age=3600; path=/'")
    finally:
        first.quit()
    second = create_driver(settings)
    try:
        second.get(f"{site_url}/blank.html")
        assert "sessao=abc" in second.execute_script("return document.cookie")
    finally:
        second.quit()

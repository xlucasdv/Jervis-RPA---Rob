"""Atualização do driver do Edge: download só quando necessário, verificação e uso pela coleta."""

import io
import os
import re
import shutil
import urllib.error
import zipfile
from pathlib import Path

import pytest
import yaml

from jervis import cli, driver
from jervis.config import Settings
from jervis.driver import DOWNLOAD_BASE, DriverError, DriverStatus, DriverUpdate, update_driver
from jervis.runner import Progress, Runner

from test_runner import ScriptedCollect, ok

PACKAGE = ("win64", "WINDOWS")


def driver_zip(version, member="msedgedriver.exe"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, f"VERSION={version}")
        archive.writestr("Driver_Notes/LICENSE", "texto")
    return buffer.getvalue()


def zip_url(version):
    return f"{DOWNLOAD_BASE}/{version}/edgedriver_win64.zip"


class FakeDownloads:
    """Site da Microsoft falso: URL → conteúdo; o resto responde 404."""

    def __init__(self, files=None, offline=False):
        self.files = files or {}
        self.offline = offline
        self.calls = []

    def __call__(self, request, timeout=None):
        self.calls.append((request.get_method(), request.full_url))
        if self.offline:
            raise urllib.error.URLError("getaddrinfo failed")
        if request.full_url not in self.files:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)
        return io.BytesIO(self.files[request.full_url])

    def downloads(self):
        return [url for method, url in self.calls if method == "GET" and url.endswith(".zip")]


def fake_version(path):
    """O 'driver' falso é um arquivo de texto com VERSION=<versão>."""
    path = Path(path)
    return path.read_text().removeprefix("VERSION=") if path.is_file() else None


def install(dest, version):
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(f"VERSION={version}")


def update(dest, edge, downloads, **kwargs):
    kwargs.setdefault("verify", lambda path: None)
    return update_driver(dest, edge, opener=downloads, version_of=fake_version, package=PACKAGE, **kwargs)


@pytest.fixture
def dest(tmp_path):
    return tmp_path / "drivers" / "msedgedriver.exe"


# --- quando baixar ----------------------------------------------------------------


def test_driver_already_matching_makes_no_network_call(dest):
    install(dest, "154.0.4258.48")
    downloads = FakeDownloads()
    result = update(dest, "154.0.4258.48", downloads)
    assert not result.updated and result.current == "154.0.4258.48"
    assert downloads.calls == []


def test_edge_major_update_downloads_exact_version(dest):
    install(dest, "154.0.4258.48")
    downloads = FakeDownloads({zip_url("155.0.4300.10"): driver_zip("155.0.4300.10")})
    result = update(dest, "155.0.4300.10", downloads)
    assert result == DriverUpdate(dest, "155.0.4300.10", "154.0.4258.48", "155.0.4300.10", updated=True)
    assert fake_version(dest) == "155.0.4300.10"
    assert list(dest.parent.iterdir()) == [dest]  # arquivo temporário removido


def test_no_previous_driver_creates_folder(dest):
    downloads = FakeDownloads({zip_url("154.0.4258.48"): driver_zip("154.0.4258.48")})
    result = update(dest, "154.0.4258.48", downloads)
    assert result.updated and result.previous is None and dest.is_file()


def test_missing_exact_build_falls_back_to_latest_of_major(dest):
    latest = "155.0.4300.62\r\n".encode("utf-16")  # a Microsoft publica em UTF-16 com BOM
    downloads = FakeDownloads({
        f"{DOWNLOAD_BASE}/LATEST_RELEASE_155_WINDOWS": latest,
        zip_url("155.0.4300.62"): driver_zip("155.0.4300.62"),
    })
    result = update(dest, "155.0.4300.48", downloads)
    assert result.updated and result.current == "155.0.4300.62"


def test_driver_already_at_latest_of_major_is_not_downloaded_again(dest):
    install(dest, "155.0.4300.62")
    downloads = FakeDownloads({f"{DOWNLOAD_BASE}/LATEST_RELEASE_155_WINDOWS": b"155.0.4300.62"})
    result = update(dest, "155.0.4300.48", downloads)
    assert not result.updated and downloads.downloads() == []


def test_force_downloads_again(dest):
    install(dest, "154.0.4258.48")
    downloads = FakeDownloads({zip_url("154.0.4258.48"): driver_zip("154.0.4258.48")})
    assert update(dest, "154.0.4258.48", downloads, force=True).updated
    assert downloads.downloads() == [zip_url("154.0.4258.48")]


def test_major_without_published_driver(dest):
    with pytest.raises(DriverError, match="não publicou driver para o Edge 199"):
        update(dest, "199.0.1.0", FakeDownloads())


# --- segurança e integridade ------------------------------------------------------


def test_invalid_signature_keeps_current_driver(dest):
    install(dest, "154.0.4258.48")
    downloads = FakeDownloads({zip_url("155.0.4300.10"): driver_zip("155.0.4300.10")})

    def reject(path):
        raise DriverError("assinatura inválida")

    with pytest.raises(DriverError, match="assinatura inválida"):
        update(dest, "155.0.4300.10", downloads, verify=reject)
    assert fake_version(dest) == "154.0.4258.48"
    assert list(dest.parent.iterdir()) == [dest]


def test_downloaded_driver_reporting_other_version_is_discarded(dest):
    downloads = FakeDownloads({zip_url("155.0.4300.10"): driver_zip("150.0.0.0")})
    with pytest.raises(DriverError, match="informou a versão 150.0.0.0, esperada 155.0.4300.10"):
        update(dest, "155.0.4300.10", downloads)
    assert not dest.exists()


@pytest.mark.parametrize("content, message", [
    (driver_zip("155.0.4300.10", member="outro.exe"), "não contém o msedgedriver"),
    (b"isto nao e um zip", "corrompido"),
])
def test_bad_package(dest, content, message):
    with pytest.raises(DriverError, match=message):
        update(dest, "155.0.4300.10", FakeDownloads({zip_url("155.0.4300.10"): content}))


def test_offline(dest):
    with pytest.raises(DriverError, match="Verifique a internet/proxy"):
        update(dest, "155.0.4300.10", FakeDownloads(offline=True))


def test_driver_in_use_cannot_be_replaced(dest, monkeypatch):
    install(dest, "154.0.4258.48")
    downloads = FakeDownloads({zip_url("155.0.4300.10"): driver_zip("155.0.4300.10")})

    def locked(src, dst):
        raise PermissionError(13, "Acesso negado")

    monkeypatch.setattr(driver.os, "replace", locked)
    with pytest.raises(DriverError, match="está em uso"):
        update(dest, "155.0.4300.10", downloads)
    assert fake_version(dest) == "154.0.4258.48"
    assert list(dest.parent.iterdir()) == [dest]


# --- uso pela coleta --------------------------------------------------------------


def test_compatibility_uses_major_version(tmp_path):
    assert DriverStatus(tmp_path, "154.0.4258.62", "154.0.4258.48").compatible
    assert not DriverStatus(tmp_path, "155.0.1.0", "154.0.4258.48").compatible
    assert not DriverStatus(tmp_path, "155.0.1.0", None).compatible


def test_update_for_requires_edge(monkeypatch):
    with pytest.raises(DriverError, match="só está disponível para o Edge"):
        driver.update_for(Settings(browser="chrome"))
    monkeypatch.setattr(driver, "edge_version", lambda: None)
    with pytest.raises(DriverError, match="Edge não encontrado"):
        driver.update_for(Settings())


def test_update_for_uses_default_path_when_driver_path_is_empty(monkeypatch):
    monkeypatch.setattr(driver, "edge_version", lambda: "154.0.4258.48")
    calls = []
    driver.update_for(Settings(), updater=lambda dest, edge, force: calls.append((dest, edge, force)))
    assert calls == [(Path(driver.DEFAULT_DRIVER_PATH), "154.0.4258.48", False)]


def test_prepare_does_nothing_when_disabled():
    driver.prepare(Settings(), print, updater=lambda s: pytest.fail("não deveria atualizar"))
    driver.prepare(Settings(driver_auto_update=True, browser="firefox"), print, updater=lambda s: pytest.fail("só Edge"))


def test_prepare_failure_only_warns():
    def offline(settings):
        raise DriverError("sem internet")

    lines = []
    settings = Settings(driver_auto_update=True, driver_path="C:/drivers/msedgedriver.exe")
    driver.prepare(settings, lines.append, updater=offline)
    assert lines == ["Atenção: não foi possível atualizar o driver do navegador (sem internet). Seguindo com o driver atual."]
    assert settings.driver_path == "C:/drivers/msedgedriver.exe"


def test_runner_updates_driver_once_and_audits(tmp_path):
    from jervis.config import AppConfig, PlatformConfig

    settings = Settings(output_dir=str(tmp_path / "output"), report_formats=["csv"],
                        audit_file=str(tmp_path / "auditoria.jsonl"), driver_auto_update=True)
    platforms = {n: PlatformConfig(name=n, kind="sophos", url=f"https://{n}.local", enabled=True) for n in ("a", "b")}
    config = AppConfig(settings=settings, platforms=platforms)
    seen, lines = [], []

    def updater(s):
        seen.append(s.driver_path)
        return DriverUpdate(Path("drivers/msedgedriver.exe"), "155.0.1.0", "154.0.4258.48", "155.0.1.0", updated=True)

    collect = ScriptedCollect({"a": [ok("a")], "b": [ok("b")]})
    Runner(config, store=object(), emit=Progress(lines.append), collect=collect, driver_updater=updater).run(list(platforms.values()))
    assert seen == [""]  # uma vez por execução, antes da primeira plataforma
    assert settings.driver_path == str(Path("drivers/msedgedriver.exe"))
    assert any("Driver do navegador atualizado: 154.0.4258.48 -> 155.0.1.0 (Edge 155.0.1.0)" in line for line in lines)
    audit = (tmp_path / "auditoria.jsonl").read_text(encoding="utf-8")
    assert '"evento": "driver_atualizado"' in audit and '"para": "155.0.1.0"' in audit


# --- comandos ---------------------------------------------------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    return tmp_path


def test_cli_driver_status(project, monkeypatch, capsys):
    monkeypatch.setattr(driver, "edge_version", lambda: "155.0.1.0")
    monkeypatch.setattr(driver, "driver_version", lambda path: "154.0.4258.48")
    assert cli.main(["-c", "platforms.yaml", "driver", "status"]) == 2
    assert "INCOMPATÍVEL" in capsys.readouterr().out
    monkeypatch.setattr(driver, "driver_version", lambda path: "155.0.1.0")
    assert cli.main(["-c", "platforms.yaml", "driver", "status"]) == 0
    assert "Situação: compatível." in capsys.readouterr().out


def test_cli_driver_update_saves_path_and_auto(project, monkeypatch, capsys):
    result = DriverUpdate(Path("drivers/msedgedriver.exe"), "155.0.1.0", None, "155.0.1.0", updated=True)
    monkeypatch.setattr(driver, "update_for", lambda settings, force=False: result)
    assert cli.main(["-c", "platforms.yaml", "driver", "update", "--auto"]) == 0
    out = capsys.readouterr().out
    assert "Driver atualizado: nenhum -> 155.0.1.0" in out
    saved = yaml.safe_load((project / "platforms.yaml").read_text(encoding="utf-8"))["settings"]
    assert saved["driver_path"] == "drivers/msedgedriver.exe" and saved["driver_auto_update"] is True

    assert cli.main(["-c", "platforms.yaml", "driver", "update", "--no-auto"]) == 0
    saved = yaml.safe_load((project / "platforms.yaml").read_text(encoding="utf-8"))["settings"]
    assert saved["driver_auto_update"] is False


def test_cli_driver_update_error(project, monkeypatch, capsys):
    def offline(settings, force=False):
        raise DriverError("Não foi possível acessar o site")

    monkeypatch.setattr(driver, "update_for", offline)
    assert cli.main(["-c", "platforms.yaml", "driver", "update"]) == 1
    assert "Erro: Não foi possível acessar o site" in capsys.readouterr().err


def test_invalid_auto_update_value(project):
    path = project / "platforms.yaml"
    text = path.read_text(encoding="utf-8")
    assert "driver_auto_update: false" in text
    path.write_text(text.replace("driver_auto_update: false", "driver_auto_update: sim"), encoding="utf-8")
    assert cli.main(["-c", "platforms.yaml", "driver", "status"]) == 1


# --- máquina real (Windows) -------------------------------------------------------

windows_only = pytest.mark.skipif(os.name != "nt", reason="verificações do Windows")


@windows_only
def test_real_edge_version():
    version = driver.edge_version()
    if version is None:
        pytest.skip("Microsoft Edge não instalado")
    assert re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version)


@windows_only
def test_real_driver_version_and_signature(test_driver_path, tmp_path):
    if not test_driver_path:
        pytest.skip("defina JERVIS_TEST_DRIVER_PATH")
    assert re.fullmatch(r"\d+\.\d+\.\d+\.\d+", driver.driver_version(Path(test_driver_path)))
    driver.verify_signature(Path(test_driver_path))

    unsigned = tmp_path / "msedgedriver.exe"
    shutil.copy(__file__, unsigned)  # um arquivo qualquer, sem assinatura
    with pytest.raises(DriverError, match="assinatura válida da Microsoft"):
        driver.verify_signature(unsigned)

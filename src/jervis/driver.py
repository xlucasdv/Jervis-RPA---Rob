"""Atualização do driver do Microsoft Edge (``msedgedriver``).

O Edge se atualiza sozinho (uma versão principal nova por mês) e o driver precisa acompanhá-lo.
Em máquinas onde o ``selenium-manager.exe`` é bloqueado pela política de controle de aplicativos,
este módulo faz o mesmo papel: descobre a versão do Edge instalado, baixa o driver correspondente do
site oficial da Microsoft, confere a assinatura digital e só então substitui o arquivo em uso.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from jervis.config import Settings
from jervis.errors import JervisError

DOWNLOAD_BASE = "https://msedgedriver.microsoft.com"
DRIVER_NAME = "msedgedriver.exe" if os.name == "nt" else "msedgedriver"
DEFAULT_DRIVER_PATH = f"drivers/{DRIVER_NAME}"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
SIGNER = "O=Microsoft Corporation"

_VERSION = re.compile(r"\d+\.\d+\.\d+\.\d+")
_EDGE_PATHS = (
    ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
    ("LOCALAPPDATA", r"Microsoft\Edge\Application\msedge.exe"),
)
_EDGE_COMMANDS = ("microsoft-edge", "microsoft-edge-stable", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")


class DriverError(JervisError):
    """Não foi possível verificar ou atualizar o driver do navegador."""


@dataclass
class DriverUpdate:
    path: Path
    edge_version: str
    previous: str | None  # versão do driver antes (None = não havia driver)
    current: str
    updated: bool


@dataclass
class DriverStatus:
    path: Path
    edge_version: str | None
    driver_version: str | None

    @property
    def compatible(self) -> bool:
        return bool(self.edge_version and self.driver_version and major(self.edge_version) == major(self.driver_version))


def major(version: str) -> str:
    return version.split(".", 1)[0]


def driver_path(settings: Settings) -> Path:
    return Path(settings.driver_path or DEFAULT_DRIVER_PATH)


# --- versões ----------------------------------------------------------------------


def edge_version() -> str | None:
    """Versão do Edge que o Selenium vai abrir (a do executável, não a do processo em execução)."""
    if os.name == "nt":
        for env, relative in _EDGE_PATHS:
            base = os.environ.get(env)
            if base and (exe := Path(base) / relative).is_file() and (version := _file_version(exe)):
                return version
        return None
    for command in _EDGE_COMMANDS:
        if version := _version_from_command([command, "--version"]):
            return version
    return None


def _file_version(path: Path) -> str | None:
    """Versão do arquivo pelos recursos do executável (Windows), sem depender do PowerShell."""
    import ctypes
    from ctypes import wintypes

    version_dll = ctypes.WinDLL("version")
    size = version_dll.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        return None
    buffer = ctypes.create_string_buffer(size)
    if not version_dll.GetFileVersionInfoW(str(path), 0, size, buffer):
        return None
    info, length = ctypes.c_void_p(), wintypes.UINT()
    if not version_dll.VerQueryValueW(buffer, "\\", ctypes.byref(info), ctypes.byref(length)):
        return None
    # VS_FIXEDFILEINFO: dwFileVersionMS e dwFileVersionLS são o 3º e o 4º DWORD.
    ms, ls = ctypes.cast(info, ctypes.POINTER(wintypes.DWORD * 4)).contents[2:4]
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def driver_version(path: Path) -> str | None:
    """Versão informada pelo próprio driver ("Microsoft Edge WebDriver 154.0.4258.48 (...)")."""
    if not Path(path).is_file():
        return None
    return _version_from_command([str(path), "--version"])


def _version_from_command(command: list[str]) -> str | None:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return None
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DriverError(f"Não foi possível executar {command[0]}: {exc}") from exc
    match = _VERSION.search(proc.stdout or "")
    return match.group(0) if match else None


def status(settings: Settings) -> DriverStatus:
    path = driver_path(settings)
    return DriverStatus(path, edge_version(), driver_version(path))


# --- download ---------------------------------------------------------------------


def _platform() -> tuple[str, str]:
    """(nome do pacote, sufixo do LATEST_RELEASE) para esta máquina."""
    import platform

    machine = platform.machine().lower()
    if sys.platform == "win32":
        return ("arm64" if machine in ("arm64", "aarch64") else "win64" if machine.endswith("64") else "win32"), "WINDOWS"
    if sys.platform == "darwin":
        return ("mac64_m1" if machine == "arm64" else "mac64"), "MACOS"
    return "linux64", "LINUX"


def verify_signature(path: Path) -> None:
    """Confere a assinatura Authenticode do driver baixado (Windows)."""
    if os.name != "nt":
        return  # fora do Windows a garantia vem só do HTTPS com o domínio da Microsoft
    literal = str(path).replace("'", "''")
    script = (f"$s = Get-AuthenticodeSignature -LiteralPath '{literal}'; "
              "$s.Status.ToString(); if ($s.SignerCertificate) { $s.SignerCertificate.Subject }")
    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DriverError(f"Não foi possível verificar a assinatura do driver baixado: {exc}") from exc
    lines = (proc.stdout or "").strip().splitlines()
    state, subject = (lines[0].strip() if lines else ""), (lines[1] if len(lines) > 1 else "")
    if state != "Valid" or SIGNER not in subject:
        raise DriverError(f"O driver baixado não tem uma assinatura válida da Microsoft (situação: {state or 'desconhecida'}); "
                          "o arquivo foi descartado.")


def update_driver(
    dest: Path,
    edge: str,
    *,
    force: bool = False,
    opener: Callable = urllib.request.urlopen,
    version_of: Callable[[Path], str | None] = driver_version,
    verify: Callable[[Path], None] = verify_signature,
    package: tuple[str, str] | None = None,
) -> DriverUpdate:
    """Garante em ``dest`` o driver da versão do Edge ``edge``; só baixa quando necessário."""
    dest = Path(dest)
    previous = version_of(dest) if dest.is_file() else None
    if previous == edge and not force:
        return DriverUpdate(dest, edge, previous, previous, updated=False)
    name, os_label = package or _platform()
    target = edge if _exists(opener, _zip_url(edge, name)) else _latest(opener, major(edge), os_label)
    if previous == target and not force:
        return DriverUpdate(dest, edge, previous, previous, updated=False)

    executable = _download(opener, _zip_url(target, name))
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.with_name(f"{dest.stem}.novo{dest.suffix}")
    staging.write_bytes(executable)
    try:
        if os.name != "nt":
            staging.chmod(0o755)
        verify(staging)
        got = version_of(staging)
        if got != target:
            raise DriverError(f"O driver baixado informou a versão {got or 'desconhecida'}, esperada {target}; o arquivo foi descartado.")
        try:
            os.replace(staging, dest)
        except PermissionError as exc:
            raise DriverError(f"Não foi possível substituir {dest}: o driver está em uso. "
                              "Aguarde o fim da coleta (ou feche os navegadores abertos pela automação) e tente de novo.") from exc
    finally:
        staging.unlink(missing_ok=True)
    return DriverUpdate(dest, edge, previous, target, updated=True)


def _zip_url(version: str, name: str) -> str:
    return f"{DOWNLOAD_BASE}/{version}/edgedriver_{name}.zip"


def _open(opener: Callable, url: str, method: str = "GET"):
    try:
        return opener(urllib.request.Request(url, method=method), timeout=60)
    except urllib.error.HTTPError:
        raise
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DriverError(f"Não foi possível acessar {DOWNLOAD_BASE} ({reason}). Verifique a internet/proxy.") from exc


def _exists(opener: Callable, url: str) -> bool:
    try:
        with _open(opener, url, "HEAD"):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            return False
        raise DriverError(f"{DOWNLOAD_BASE} respondeu HTTP {exc.code}.") from exc


def _latest(opener: Callable, major_version: str, os_label: str) -> str:
    url = f"{DOWNLOAD_BASE}/LATEST_RELEASE_{major_version}_{os_label}"
    try:
        with _open(opener, url) as response:
            raw = response.read(1024)
    except urllib.error.HTTPError as exc:
        raise DriverError(f"A Microsoft não publicou driver para o Edge {major_version} (HTTP {exc.code}).") from exc
    # O arquivo vem em UTF-16 com BOM.
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    match = _VERSION.search(text)
    if not match:
        raise DriverError(f"Resposta inesperada de {url}.")
    return match.group(0)


def _download(opener: Callable, url: str) -> bytes:
    try:
        with _open(opener, url) as response:
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise DriverError(f"Falha ao baixar {url} (HTTP {exc.code}).") from exc
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise DriverError(f"Arquivo maior que o esperado em {url}; download descartado.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            member = next((m for m in archive.namelist() if Path(m).name in ("msedgedriver.exe", "msedgedriver")), None)
            if member is None:
                raise DriverError(f"O pacote {url} não contém o msedgedriver.")
            return archive.read(member)
    except zipfile.BadZipFile as exc:
        raise DriverError(f"O pacote baixado de {url} está corrompido.") from exc


# --- uso pela coleta --------------------------------------------------------------


def update_for(settings: Settings, force: bool = False, updater: Callable[..., DriverUpdate] = update_driver) -> DriverUpdate:
    if settings.browser != "edge":
        raise DriverError(f"A atualização automática do driver só está disponível para o Edge (navegador atual: {settings.browser}).")
    edge = edge_version()
    if not edge:
        raise DriverError("Microsoft Edge não encontrado nesta máquina.")
    return updater(driver_path(settings), edge, force=force)


def prepare(settings: Settings, emit: Callable[[str], None], record: Callable[..., None] | None = None,
            updater: Callable[[Settings], DriverUpdate] = update_for) -> None:
    """Antes de abrir o navegador: atualiza o driver se ``driver_auto_update`` estiver ativo.

    Uma falha aqui não interrompe a coleta: o driver atual pode continuar servindo.
    """
    if not (settings.driver_auto_update and settings.browser == "edge"):
        return
    try:
        result = updater(settings)
    except DriverError as exc:
        emit(f"Atenção: não foi possível atualizar o driver do navegador ({exc}). Seguindo com o driver atual.")
        return
    settings.driver_path = str(result.path)
    if result.updated:
        emit(f"Driver do navegador atualizado: {result.previous or 'nenhum'} -> {result.current} (Edge {result.edge_version}).")
        if record:
            record("driver_atualizado", de=result.previous, para=result.current, edge=result.edge_version, caminho=str(result.path))

"""Base dos coletores: navegação entre páginas, tentativas e registro de falhas.

Cada plataforma declara seus conjuntos de dados (``DatasetSpec``): quais páginas
visitar e como ler a tabela de cada uma. A base garante que:
  * cada página é coletada de forma isolada — falha em uma não impede as demais;
  * falhas transitórias (rede, lentidão) são tentadas novamente;
  * toda falha é classificada (``IssueCategory``), registrada no resultado e no
    log, com captura de tela opcional;
  * retorno à tela de login (sessão expirada) interrompe a coleta com clareza.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, ClassVar, Mapping
from urllib.parse import urldefrag, urljoin

from selenium.common.exceptions import (
    InvalidSessionIdException,
    NoSuchWindowException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

from jervis.auth.profiles import PROFILES
from jervis.collectors.models import WARNING, CollectionResult, Issue
from jervis.collectors.parsing import DATE_ORDERS
from jervis.collectors.table import TABLE_SELECTOR_KEYS, TableScraper, TableSpec
from jervis.config import PlatformConfig, Settings
from jervis.diagnostics import save_screenshot
from jervis.errors import (
    CollectionError,
    CollectionTimeoutError,
    ConfigError,
    IssueCategory,
    NavigationError,
    SessionExpiredError,
    UiChangedError,
)

log = logging.getLogger(__name__)

_NETWORK_ERRORS = ("ERR_NAME_NOT_RESOLVED", "ERR_CONNECTION", "ERR_INTERNET_DISCONNECTED", "ERR_ADDRESS_UNREACHABLE", "ERR_TIMED_OUT")

# Navegadores nem sempre lançam exceção em falha de rede: exibem uma página de erro própria
# (Chromium: #main-frame-error; Firefox: about:neterror). Também lê o status HTTP da navegação.
_PAGE_STATUS_JS = r"""
const nav = performance.getEntriesByType('navigation')[0];
let netError = null;
if (document.getElementById('main-frame-error')) {
  const code = document.querySelector('.error-code');
  netError = (code && code.textContent.trim()) || 'erro de rede';
} else if (document.documentURI.startsWith('about:neterror')) {
  netError = new URLSearchParams(document.documentURI.split('?')[1] || '').get('e') || 'erro de rede';
}
return {netError, status: nav && nav.responseStatus ? nav.responseStatus : 0};
"""


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    pages: Mapping[str, str]  # origem (ex.: "servidor") → caminho relativo à plataforma ou URL completa
    table: TableSpec
    normalize: Callable[[dict[str, Any]], dict[str, Any]] | None = None


class Collector:
    kind: ClassVar[str]
    # Parâmetros próprios do coletor aceitos em ``params`` (além de timeout, retries e date_order).
    option_names: ClassVar[tuple[str, ...]] = ()

    def __init__(self, platform: PlatformConfig, settings: Settings, poll_interval: float = 0.5, settle: float = 3.0):
        self.platform = platform
        self.settings = settings
        self.poll_interval = poll_interval
        self.settle = settle
        params = dict(platform.params)
        self.timeout = _positive_int(params.pop("timeout", settings.collect_timeout), f"{self._where}.timeout")
        self.retries = _non_negative_int(params.pop("retries", 1), f"{self._where}.retries")
        self.date_order = params.pop("date_order", "auto")
        if self.date_order not in DATE_ORDERS:
            raise ConfigError(f"{self._where}.date_order deve ser um de: {', '.join(DATE_ORDERS)}.")
        self.configure({name: params.pop(name) for name in self.option_names if name in params})
        self.datasets = self._build_datasets(params)
        self._login_profile = PROFILES[platform.kind].with_overrides(platform.selectors)
        self._progress: Callable[[str], None] = lambda message: None

    def default_datasets(self) -> dict[str, DatasetSpec]:
        raise NotImplementedError

    def configure(self, options: dict[str, Any]) -> None:
        """Valida e aplica os parâmetros de ``option_names`` (chamado antes de montar os conjuntos)."""

    def summarize(self, result: CollectionResult) -> None:
        """Pós-processa os dados (ex.: cruzar conjuntos) e gera destaques; chamado ao fim da coleta."""

    @property
    def name(self) -> str:
        return self.platform.name

    @property
    def _where(self) -> str:
        return f"platforms.{self.platform.name}.params"

    # --- execução -----------------------------------------------------------------

    def collect(
        self,
        driver: WebDriver,
        result: CollectionResult,
        base_url: str | None = None,
        only: set[str] | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        """Coleta todos os conjuntos, ou só as etapas ``only`` ("conjunto/origem"), para reprocessamento."""
        self._progress = progress or (lambda message: None)
        try:
            self._collect_all(driver, result, base_url or driver.current_url, only)
        finally:
            self.summarize(result)

    def inspect(
        self, driver: WebDriver, base_url: str | None = None, progress: Callable[[str], None] | None = None,
        screenshot_dir: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Verifica cada página configurada (endereço, tabela, colunas) sem coletar dados (Feature 9.2)."""
        progress = progress or (lambda message: None)
        base = base_url or driver.current_url
        checks = []
        for ds in self.datasets.values():
            for origin, path in ds.pages.items():
                stage, url = f"{ds.name}/{origin}", urljoin(base, path)
                check: dict[str, Any] = {"etapa": stage, "url": url}
                try:
                    self._navigate(driver, url)
                    details = TableScraper(
                        driver, ds.table, timeout=self.timeout, poll_interval=self.poll_interval,
                        settle=self.settle, interrupt=lambda: self._check_session(driver),
                    ).inspect()
                    check.update(details)
                    if details["obrigatorias_ausentes"]:
                        check["resultado"] = "falha"
                        check["mensagem"] = f"coluna(s) obrigatória(s) ausente(s): {', '.join(details['obrigatorias_ausentes'])}"
                    elif details["esperadas_ausentes"]:
                        check["resultado"] = "aviso"
                        check["mensagem"] = f"coluna(s) esperada(s) ausente(s): {', '.join(details['esperadas_ausentes'])}"
                    else:
                        check["resultado"] = "ok"
                        check["mensagem"] = f"{details['linhas_primeira_pagina']} linha(s) na 1ª página"
                except CollectionError as exc:
                    check.update(resultado="falha", categoria=str(exc.category), mensagem=str(exc))
                if screenshot_dir is not None:
                    check["captura"] = _screenshot(driver, screenshot_dir / f"{self.name}-{stage.replace('/', '_')}.png")
                progress(f"{stage}: {check['resultado'].upper()} — {check['mensagem']}")
                checks.append(check)
        return checks

    def stages(self) -> list[str]:
        return [f"{ds.name}/{origin}" for ds in self.datasets.values() for origin in ds.pages]

    def _collect_all(self, driver: WebDriver, result: CollectionResult, base: str, only: set[str] | None = None) -> None:
        pending = [
            (ds, origin, path)
            for ds in self.datasets.values()
            for origin, path in ds.pages.items()
            if only is None or f"{ds.name}/{origin}" in only
        ]
        for ds in self.datasets.values():
            if ds.pages:  # conjuntos desativados (sem páginas) não aparecem no resultado
                result.datasets.setdefault(ds.name, [])

        for position, (ds, origin, path) in enumerate(pending):
            try:
                rows = self._collect_page(driver, result, ds, origin, urljoin(base, path))
            except SessionExpiredError:
                skipped = [f"{d.name}/{o}" for d, o, _ in pending[position + 1 :]]
                if skipped:
                    result.add_issue(Issue(
                        stage="coleta",
                        category=IssueCategory.AUTHENTICATION,
                        message=f"Coleta interrompida pela perda da sessão; não coletado: {', '.join(skipped)}.",
                    ))
                return
            result.datasets[ds.name].extend(rows)

    def _collect_page(
        self, driver: WebDriver, result: CollectionResult, ds: DatasetSpec, origin: str, url: str
    ) -> list[dict[str, Any]]:
        stage = f"{ds.name}/{origin}"
        attempts = 1 + self.retries
        for attempt in range(1, attempts + 1):
            try:
                log.info("[%s] Coletando %s em %s (tentativa %d/%d)", self.name, stage, url, attempt, attempts)
                self._navigate(driver, url)
                table = TableScraper(
                    driver, ds.table, timeout=self.timeout, poll_interval=self.poll_interval,
                    settle=self.settle, interrupt=lambda: self._check_session(driver),
                ).scrape()
            except CollectionError as exc:
                if exc.retryable and attempt < attempts:
                    log.warning("[%s] %s: %s Tentando novamente.", self.name, stage, exc)
                    continue
                self._record_failure(driver, result, stage, exc.category, str(exc), url)
                if isinstance(exc, SessionExpiredError):
                    raise
                return []
            except (InvalidSessionIdException, NoSuchWindowException):
                raise  # navegador encerrado: não há como continuar
            except WebDriverException as exc:
                message = f"Erro inesperado do navegador: {(exc.msg or str(exc)).strip()}"
                self._record_failure(driver, result, stage, IssueCategory.UNEXPECTED, message, url)
                return []

            for warning in table.warnings:
                result.add_issue(Issue(stage=stage, category=IssueCategory.UI_CHANGED, message=warning, severity=WARNING, url=url))
            rows = [{**row, "origem": origin} for row in table.rows]
            if ds.normalize:
                rows = [ds.normalize(row) for row in rows]
            # Campos auxiliares ("_<campo>_classes") servem só ao normalizador.
            rows = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows]
            log.info("[%s] %s: %d registro(s) em %d página(s)", self.name, stage, len(rows), table.pages)
            self._progress(f"{stage}: {len(rows)} registro(s) em {table.pages} página(s)")
            return rows
        return []  # inalcançável: a última tentativa sempre retorna ou lança

    # --- navegação ----------------------------------------------------------------

    def _navigate(self, driver: WebDriver, url: str) -> None:
        try:
            if urldefrag(url).fragment and urldefrag(url).url == urldefrag(driver.current_url).url:
                # Rotas de SPA (/ui/#/devices → /ui/#/activities) só trocam o fragmento e não recarregam
                # a página: a tabela anterior continuaria na tela e seria lida como se fosse a nova.
                driver.get("about:blank")
            driver.get(url)
        except TimeoutException as exc:
            raise CollectionTimeoutError(
                f"A página não carregou em {self.settings.page_load_timeout}s: {url}"
            ) from exc
        except (InvalidSessionIdException, NoSuchWindowException):
            raise
        except WebDriverException as exc:
            detail = (exc.msg or str(exc)).strip().splitlines()[0]
            if any(code in detail for code in _NETWORK_ERRORS):
                raise NavigationError(
                    f"Plataforma inacessível ao abrir {url}: {detail}", category=IssueCategory.UNAVAILABLE
                ) from exc
            raise NavigationError(f"Não foi possível abrir {url}: {detail}") from exc
        self._check_page_status(driver, url)
        self._check_session(driver)

    @staticmethod
    def _check_page_status(driver: WebDriver, url: str) -> None:
        page = driver.execute_script(_PAGE_STATUS_JS) or {}
        if page.get("netError"):
            raise NavigationError(
                f"Plataforma inacessível ao abrir {url}: {page['netError']}", category=IssueCategory.UNAVAILABLE
            )
        status = page.get("status") or 0
        if status >= 500:
            raise NavigationError(
                f"A plataforma respondeu com erro HTTP {status} em {url} (instabilidade no servidor).",
                category=IssueCategory.UNAVAILABLE,
            )
        if status == 404:
            raise UiChangedError(
                f"Página não encontrada (HTTP 404): {url}. O endereço pode ter mudado; ajuste params.<conjunto>.pages."
            )

    def _check_session(self, driver: WebDriver) -> None:
        for selector in self._login_profile.password:
            if any(el.is_displayed() for el in driver.find_elements(By.CSS_SELECTOR, selector)):
                raise SessionExpiredError(
                    "A plataforma voltou para a tela de login: a sessão expirou ou foi encerrada. "
                    "Execute a coleta novamente; se persistir, verifique se o usuário tem acesso a esta área."
                )

    def _record_failure(
        self, driver: WebDriver, result: CollectionResult, stage: str, category: IssueCategory, message: str, url: str
    ) -> None:
        screenshot = save_screenshot(driver, self.settings, self.name, stage)
        result.add_issue(Issue(stage=stage, category=category, message=message, url=url, screenshot=screenshot))
        self._progress(f"{stage}: falha ({category})")

    # --- configuração -------------------------------------------------------------

    def _build_datasets(self, params: dict[str, Any]) -> dict[str, DatasetSpec]:
        datasets = self.default_datasets()
        unknown = sorted(set(params) - set(datasets))
        if unknown:
            valid = ", ".join(["timeout", "retries", "date_order", *self.option_names, *datasets])
            raise ConfigError(f"Parâmetro(s) desconhecido(s) em {self._where}: {', '.join(unknown)}. Válidos: {valid}.")
        for name, override in params.items():
            datasets[name] = self._apply_override(datasets[name], override, f"{self._where}.{name}")
        return datasets

    @staticmethod
    def _apply_override(ds: DatasetSpec, override: Any, where: str) -> DatasetSpec:
        if not isinstance(override, dict):
            raise ConfigError(f"{where} deve ser um mapeamento (pages, columns, table).")
        unknown = sorted(set(override) - {"pages", "columns", "table"})
        if unknown:
            raise ConfigError(f"Chave(s) desconhecida(s) em {where}: {', '.join(unknown)}. Válidas: pages, columns, table.")

        pages = ds.pages
        if "pages" in override:
            pages = override["pages"] or {}
            if not isinstance(pages, dict) or not all(isinstance(k, str) and isinstance(v, str) and v for k, v in pages.items()):
                raise ConfigError(f"{where}.pages deve mapear origem → caminho (ex.: servidor: /manage/server/servers-list).")

        columns = {k: _selector_list(v, f"{where}.columns.{k}") for k, v in (override.get("columns") or {}).items()}

        table_raw = dict(override.get("table") or {})
        max_pages = table_raw.pop("max_pages", None)
        if max_pages is not None:
            max_pages = _positive_int(max_pages, f"{where}.table.max_pages")
        bad = sorted(set(table_raw) - set(TABLE_SELECTOR_KEYS))
        if bad:
            raise ConfigError(f"Chave(s) desconhecida(s) em {where}.table: {', '.join(bad)}. Válidas: {', '.join(TABLE_SELECTOR_KEYS)}, max_pages.")
        selectors = {k: _selector_list(v, f"{where}.table.{k}") for k, v in table_raw.items()}

        return replace(ds, pages=pages, table=ds.table.with_overrides(columns, selectors, max_pages))


def _screenshot(driver: WebDriver, path: Path) -> str | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        driver.save_screenshot(str(path))
        return str(path)
    except Exception:  # diagnóstico: nunca interrompe a verificação
        log.warning("Não foi possível salvar a captura %s", path, exc_info=True)
        return None


def _selector_list(value: Any, where: str) -> tuple[str, ...]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or not all(isinstance(v, str) and v.strip() for v in values):
        raise ConfigError(f"{where} deve ser um texto ou uma lista de textos.")
    return tuple(values)


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{where} deve ser um inteiro positivo.")
    return value


def _non_negative_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConfigError(f"{where} deve ser um inteiro maior ou igual a zero.")
    return value

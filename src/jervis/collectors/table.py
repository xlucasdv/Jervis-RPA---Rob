"""Extração de tabelas paginadas de aplicações web (SPA), resistente a mudanças de layout.

As colunas são localizadas pelo *texto do cabeçalho* (com sinônimos em português e
inglês), não pela posição: reordenar ou incluir colunas na interface não quebra a
coleta. Quando uma coluna obrigatória some, a falha é reportada como alteração de
interface, listando as colunas encontradas.

A leitura das linhas é feita em uma única chamada JavaScript por página, o que
mantém a coleta rápida mesmo com milhares de dispositivos.
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping

from selenium.common.exceptions import (
    ElementClickInterceptedException,
    InvalidSessionIdException,
    NoSuchWindowException,
    WebDriverException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

from jervis.errors import CollectionTimeoutError, UiChangedError

log = logging.getLogger(__name__)

DEFAULT_ROWS = ("table tbody tr", "[role='rowgroup'] [role='row']")
DEFAULT_CELLS = ("td", "[role='cell']", "[role='gridcell']")
DEFAULT_HEADERS = ("table thead th", "[role='columnheader']")
DEFAULT_NEXT_PAGE = (
    "[aria-label='Próxima página']",
    "[aria-label='Next page']",
    "[aria-label='Next']",
    ".pagination-next",
    "li.next > a",
)
DEFAULT_LOADING = ("[role='progressbar']", ".loading", ".spinner")
DEFAULT_EMPTY = (".empty-state", "[data-empty-state]", ".no-data", ".no-results")

TABLE_SELECTOR_KEYS = ("rows", "cells", "headers", "next_page", "loading", "empty")

# Lê cabeçalhos, linhas e indicadores de carregamento/lista vazia de uma só vez.
# Células mescladas (colspan) são expandidas, para que os índices de cabeçalho e linhas
# coincidam; linhas de célula única (separadores de data, "nenhum registro") são ignoradas.
_SNAPSHOT_JS = r"""
const [rowSel, cellSel, headSel, loadingSel, emptySel, wantClasses] = arguments;
const visible = el => el.getClientRects().length > 0;
const textOf = el => {
  const text = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
  if (text) return text;
  // Colunas de ícone (ex.: severidade) costumam trazer o valor em aria-label/title.
  const labelled = el.matches('[aria-label],[title]') ? el : el.querySelector('[aria-label],[title]');
  return labelled ? (labelled.getAttribute('aria-label') || labelled.getAttribute('title') || '').trim() : '';
};
// Classes CSS da célula e de seus elementos internos (ex.: etiqueta verde/vermelha de disponibilidade).
const classesOf = el => Array.from(new Set([el, ...el.querySelectorAll('[class]')]
  .flatMap(e => Array.from(e.classList)))).join(' ');
const span = el => Math.max(1, parseInt(el.getAttribute('colspan') || '1', 10) || 1);
const expand = (cells, fn) => cells.flatMap(c => [fn(c), ...Array(span(c) - 1).fill('')]);
const all = sel => sel ? Array.from(document.querySelectorAll(sel)).filter(visible) : [];
const headerCells = all(headSel);
const width = headerCells.reduce((n, h) => n + span(h), 0);
const rows = all(rowSel)
  .filter(r => !r.querySelector(headSel))
  .map(r => Array.from(r.querySelectorAll(cellSel)).filter(c => c.closest('tr, [role="row"]') === r))
  .filter(cells => cells.some(c => textOf(c)) && !(width > 2 && cells.length === 1));
return {
  headers: expand(headerCells, textOf),
  rows: rows.map(cells => expand(cells, textOf)),
  classes: wantClasses ? rows.map(cells => expand(cells, classesOf)) : [],
  loading: all(loadingSel).length > 0,
  empty: all(emptySel).length > 0,
};
"""

_EMPTY_SNAPSHOT = {"headers": [], "rows": [], "classes": [], "loading": True, "empty": False}


@dataclass(frozen=True)
class TableSpec:
    # campo de saída → rótulos aceitos no cabeçalho; "#3" indica a 3ª coluna (posição fixa).
    columns: Mapping[str, tuple[str, ...]]
    # Ausência de coluna obrigatória = erro (interface alterada); das demais = aviso,
    # exceto as "extras", que podem simplesmente não existir em algumas telas.
    required: tuple[str, ...] = ()
    extras: tuple[str, ...] = ()
    # Campos cujas classes CSS também são capturadas, em "_<campo>_classes" (para o normalizador).
    class_fields: tuple[str, ...] = ()
    rows: tuple[str, ...] = DEFAULT_ROWS
    cells: tuple[str, ...] = DEFAULT_CELLS
    headers: tuple[str, ...] = DEFAULT_HEADERS
    next_page: tuple[str, ...] = DEFAULT_NEXT_PAGE
    loading: tuple[str, ...] = DEFAULT_LOADING
    empty: tuple[str, ...] = DEFAULT_EMPTY
    max_pages: int = 200

    def with_overrides(
        self,
        columns: Mapping[str, tuple[str, ...]] | None = None,
        selectors: Mapping[str, tuple[str, ...]] | None = None,
        max_pages: int | None = None,
    ) -> TableSpec:
        merged = {**self.columns, **(columns or {})}
        return replace(self, columns=merged, max_pages=max_pages or self.max_pages, **(selectors or {}))


@dataclass
class TableData:
    rows: list[dict[str, str | None]] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    pages: int = 0
    warnings: list[str] = field(default_factory=list)


def normalize_label(text: str) -> str:
    """'Última atividade ▲' → 'ultima atividade'."""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text).split())


def map_columns(headers: list[str], columns: Mapping[str, tuple[str, ...]]) -> dict[str, int]:
    """Associa cada campo ao índice da coluna: alias exato primeiro, depois prefixo."""
    normalized = [normalize_label(h) for h in headers]
    mapping: dict[str, int] = {}
    for field_name, aliases in columns.items():
        index = _find_column(normalized, aliases, lambda h, a: h == a)
        if index is None:
            index = _find_column(normalized, aliases, lambda h, a: bool(a) and h.startswith(a))
        if index is not None:
            mapping[field_name] = index
    return mapping


def _find_column(headers: list[str], aliases: tuple[str, ...], match: Callable[[str, str], bool]) -> int | None:
    for alias in aliases:
        if alias.startswith("#") and alias[1:].isdigit():
            return int(alias[1:]) - 1
        wanted = normalize_label(alias)
        for i, header in enumerate(headers):
            if match(header, wanted):
                return i
    return None


class TableScraper:
    def __init__(
        self,
        driver: WebDriver,
        spec: TableSpec,
        timeout: float = 30.0,
        poll_interval: float = 0.5,
        settle: float = 3.0,
        interrupt: Callable[[], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.driver = driver
        self.spec = spec
        self.timeout = timeout
        self.poll_interval = poll_interval
        # Tempo de espera por linhas quando só o cabeçalho apareceu e não há indicação de lista vazia.
        self.settle = min(settle, timeout)
        # Chamado a cada ciclo de espera; pode lançar exceção (ex.: sessão expirada).
        self.interrupt = interrupt
        self._clock = clock
        self._sleep = sleep

    def inspect(self) -> dict[str, Any]:
        """Verifica a tabela sem coletar: colunas encontradas, mapeamento, ausências e paginação."""
        snapshot = self._wait_ready()
        headers = snapshot["headers"]
        mapping = map_columns(headers, self.spec.columns)
        first_row = next((cells for cells in snapshot["rows"] if _is_data_row(cells, len(headers))), None)
        return {
            "colunas_na_pagina": [h for h in headers if h],
            "mapeamento": {f: headers[i] if i < len(headers) else f"#{i + 1}" for f, i in mapping.items()},
            "obrigatorias_ausentes": [f for f in self.spec.required if f not in mapping],
            "esperadas_ausentes": [f for f in self.spec.columns
                                   if f not in mapping and f not in self.spec.required and f not in self.spec.extras],
            "linhas_primeira_pagina": sum(1 for cells in snapshot["rows"] if _is_data_row(cells, len(headers))),
            "exemplo": _map_row(first_row, [], mapping, replace(self.spec, class_fields=())) if first_row else None,
            "paginacao": self._next_page_button() is not None,
            "lista_vazia": bool(snapshot["empty"]),
        }

    def scrape(self) -> TableData:
        snapshot = self._wait_ready()
        data = TableData(headers=snapshot["headers"])
        mapping = self._column_mapping(data)

        seen: set[tuple] = set()
        while True:
            signature = _signature(snapshot["rows"])
            if signature in seen:
                data.warnings.append("A paginação retornou uma página repetida; coleta da tabela encerrada.")
                break
            seen.add(signature)
            data.pages += 1
            classes = snapshot.get("classes") or [[] for _ in snapshot["rows"]]
            data.rows.extend(
                _map_row(cells, cell_classes, mapping, self.spec)
                for cells, cell_classes in zip(snapshot["rows"], classes)
                if _is_data_row(cells, len(data.headers))
            )

            if data.pages >= self.spec.max_pages:
                data.warnings.append(f"Limite de {self.spec.max_pages} páginas atingido; a tabela pode ter mais registros.")
                break
            button = self._next_page_button()
            if button is None:
                break
            self._click(button)
            snapshot = self._wait_page_change(signature)
        return data

    # --- espera -----------------------------------------------------------------

    def _wait_ready(self) -> dict[str, Any]:
        deadline = self._clock() + self.timeout
        headers_since: float | None = None
        while True:
            if self.interrupt:
                self.interrupt()
            snap = self._snapshot()
            now = self._clock()
            if not snap["loading"]:
                if snap["rows"] or snap["empty"]:
                    return snap
                if snap["headers"]:
                    headers_since = headers_since or now
                    if now - headers_since >= self.settle:
                        return snap
            if now >= deadline:
                if snap["loading"]:
                    raise CollectionTimeoutError(f"A página continuou carregando após {self.timeout:.0f}s.")
                raise UiChangedError(
                    f"Tabela não encontrada na página {self.driver.current_url} após {self.timeout:.0f}s "
                    f"(linhas esperadas em: {', '.join(self.spec.rows)}). "
                    "O endereço da página ou o layout da plataforma pode ter mudado."
                )
            self._sleep(self.poll_interval)

    def _wait_page_change(self, previous: tuple) -> dict[str, Any]:
        deadline = self._clock() + self.timeout
        while True:
            if self.interrupt:
                self.interrupt()
            snap = self._snapshot()
            if not snap["loading"] and (snap["rows"] or snap["empty"]) and _signature(snap["rows"]) != previous:
                return snap
            if self._clock() >= deadline:
                raise CollectionTimeoutError(f"A próxima página da tabela não carregou em {self.timeout:.0f}s.")
            self._sleep(self.poll_interval)

    def _snapshot(self) -> dict[str, Any]:
        spec = self.spec
        try:
            return self.driver.execute_script(
                _SNAPSHOT_JS,
                ", ".join(spec.rows),
                ", ".join(spec.cells),
                ", ".join(spec.headers),
                ", ".join(spec.loading),
                ", ".join(spec.empty),
                bool(spec.class_fields),
            )
        except (InvalidSessionIdException, NoSuchWindowException):
            raise
        except WebDriverException:
            # Página em recarga (paginação por link): trata como "carregando" e tenta de novo.
            return dict(_EMPTY_SNAPSHOT)

    # --- colunas ----------------------------------------------------------------

    def _column_mapping(self, data: TableData) -> dict[str, int]:
        mapping = map_columns(data.headers, self.spec.columns)
        missing_required = [f for f in self.spec.required if f not in mapping]
        if missing_required:
            found = ", ".join(f"'{h}'" for h in data.headers if h) or "nenhuma"
            raise UiChangedError(
                f"Coluna(s) obrigatória(s) não encontrada(s): {', '.join(missing_required)}. "
                f"Colunas na página: {found}. A interface pode ter mudado; ajuste os rótulos em "
                "params.<conjunto>.columns se necessário."
            )
        missing = [f for f in self.spec.columns if f not in mapping and f not in self.spec.extras]
        if missing:
            data.warnings.append(f"Coluna(s) não encontrada(s) na tela (ficarão vazias): {', '.join(missing)}.")
        return mapping

    # --- paginação --------------------------------------------------------------

    def _next_page_button(self) -> WebElement | None:
        for selector in self.spec.next_page:
            for el in self.driver.find_elements(By.CSS_SELECTOR, selector):
                if el.is_displayed() and _is_enabled(el):
                    return el
        return None

    def _click(self, element: WebElement) -> None:
        try:
            element.click()
        except ElementClickInterceptedException:
            self.driver.execute_script("arguments[0].click();", element)


def _is_enabled(el: WebElement) -> bool:
    if not el.is_enabled() or el.get_attribute("aria-disabled") == "true":
        return False
    classes = (el.get_attribute("class") or "").split()
    return "disabled" not in classes


def _map_row(cells: list[str], classes: list[str], mapping: dict[str, int], spec: TableSpec) -> dict[str, str | None]:
    # Todos os campos sempre presentes (None quando a coluna não existe), para um esquema estável.
    row: dict[str, str | None] = {}
    for f in spec.columns:
        i = mapping.get(f)
        row[f] = (cells[i] or None) if i is not None and i < len(cells) else None
    for f in spec.class_fields:
        i = mapping.get(f)
        row[f"_{f}_classes"] = classes[i] if i is not None and i < len(classes) else ""
    return row


def _is_data_row(cells: list[str], header_count: int) -> bool:
    # Ignora linhas vazias e "placeholders" de célula única ("Nenhum registro encontrado").
    if not any(cells):
        return False
    return not (header_count > 2 and len(cells) == 1)


def _signature(rows: list[list[str]]) -> tuple:
    return tuple(tuple(r) for r in rows)

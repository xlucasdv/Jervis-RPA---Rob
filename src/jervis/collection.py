"""Execução da coleta de uma plataforma e gravação do resultado."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from selenium.common.exceptions import WebDriverException

from jervis.browser import create_driver
from jervis.collectors import build_collector
from jervis.collectors.models import CollectionResult, Issue, now_iso
from jervis.config import PlatformConfig, Settings
from jervis.credentials import CredentialStore
from jervis.errors import (
    AuthenticationError,
    BrowserError,
    ConfigError,
    CredentialError,
    IssueCategory,
    PlatformUnavailableError,
)
from jervis.fileutil import atomic_write_text
from jervis.security import redact
from jervis.session import DriverFactory, platform_session

log = logging.getLogger(__name__)


def run_collection(
    platform: PlatformConfig,
    settings: Settings,
    store: CredentialStore,
    driver_factory: DriverFactory = create_driver,
    only: set[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> CollectionResult:
    """Autentica e coleta a plataforma (ou só as etapas ``only``). Nunca lança: falhas vão para ``result.issues``."""
    progress = progress or (lambda message: None)
    result = CollectionResult(platform=platform.name, kind=platform.kind, environment=platform.environment)

    def fail(stage: str, category: IssueCategory, message: str) -> None:
        result.add_issue(Issue(stage=stage, category=category, message=message))

    try:
        collector = build_collector(platform, settings)  # valida params antes de abrir o navegador
        progress("autenticando...")
        with platform_session(platform, settings, store, driver_factory) as (driver, login):
            progress(f"login realizado{' com MFA' if login.used_mfa else ''}")
            collector.collect(driver, result, base_url=login.url, only=only, progress=progress)
    except AuthenticationError as exc:
        fail("autenticacao", IssueCategory.AUTHENTICATION, exc.message)
    except (ConfigError, CredentialError) as exc:
        fail("configuracao", IssueCategory.CONFIGURATION, str(exc))
    except (PlatformUnavailableError, BrowserError) as exc:
        fail("acesso", IssueCategory.UNAVAILABLE, str(exc))
    except WebDriverException as exc:
        log.exception("[%s] Erro do navegador durante a coleta", platform.name)
        fail("coleta", IssueCategory.UNEXPECTED, f"O navegador falhou durante a coleta: {(exc.msg or str(exc)).strip()}")
    except Exception as exc:  # erro de programação: registra e preserva o que já foi coletado
        log.exception("[%s] Erro inesperado durante a coleta", platform.name)
        fail("coleta", IssueCategory.UNEXPECTED, f"Erro inesperado ({type(exc).__name__}): {exc}")
    finally:
        result.finished_at = now_iso()
    return result


def new_run_dir(base: str | Path) -> Path:
    return Path(base) / datetime.now().strftime("%Y%m%d-%H%M%S")


def save_result(result: CollectionResult, run_dir: Path) -> Path:
    """Grava ``<run_dir>/<plataforma>.json`` de forma atômica, com segredos mascarados."""
    text = redact(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return atomic_write_text(run_dir / f"{result.platform}.json", text)


# --- reprocessamento ------------------------------------------------------------------

# Falhas que uma nova tentativa não resolve: exigem correção da configuração.
_NOT_RETRYABLE = {IssueCategory.CONFIGURATION}


def failed_stages(result: dict[str, Any] | CollectionResult) -> set[str] | None:
    """O que reprocessar: ``set()`` = nada; ``None`` = a plataforma inteira; senão, as etapas "conjunto/origem".

    Falhas de página ("dispositivos/servidor") permitem repetir só aquela página. Falhas fora
    das páginas (autenticação, acesso, sessão interrompida) exigem repetir a plataforma toda.
    """
    issues = result.issues if isinstance(result, CollectionResult) else [
        Issue(**{**i, "category": IssueCategory(i["category"])}) for i in result.get("issues", [])
    ]
    errors = [i for i in issues if i.severity == "erro" and i.category not in _NOT_RETRYABLE]
    if not errors:
        return set()
    if any("/" not in i.stage for i in errors):
        return None
    return {i.stage for i in errors}


def merge_retry(previous: CollectionResult, retry: CollectionResult, stages: set[str] | None) -> CollectionResult:
    """Combina uma nova tentativa com o resultado anterior.

    Reprocessamento completo (``stages is None``): vale a nova tentativa. Parcial: as linhas e
    falhas das etapas repetidas são substituídas; o restante do resultado anterior é mantido.
    """
    if stages is None:
        retry.attempts = previous.attempts + 1
        return retry

    def stage_of(dataset: str, row: dict[str, Any]) -> str:
        return f"{dataset}/{row.get('origem')}"

    datasets = {
        name: [row for row in rows if stage_of(name, row) not in stages]
        for name, rows in previous.datasets.items()
    }
    for name, rows in retry.datasets.items():
        datasets.setdefault(name, []).extend(rows)
    issues = [i for i in previous.issues if i.stage not in stages] + list(retry.issues)
    return CollectionResult(
        platform=previous.platform,
        kind=previous.kind,
        environment=previous.environment,
        started_at=previous.started_at,
        finished_at=retry.finished_at,
        datasets=datasets,
        issues=issues,
        summary=previous.summary,
        attempts=previous.attempts + 1,
    )


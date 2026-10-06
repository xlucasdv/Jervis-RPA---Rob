"""Resultado de uma coleta: dados por conjunto e falhas registradas."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from jervis.errors import IssueCategory
from jervis.logging_setup import FILE_ONLY
from jervis.security import redact

log = logging.getLogger(__name__)

ERROR = "erro"
WARNING = "aviso"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Issue:
    stage: str  # ex.: "autenticacao", "dispositivos/computador"
    category: IssueCategory
    message: str
    severity: str = ERROR
    url: str | None = None
    screenshot: str | None = None
    timestamp: str = field(default_factory=now_iso)


@dataclass
class CollectionResult:
    platform: str
    kind: str
    environment: str = ""
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    datasets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)
    # Destaques calculados pelo coletor (ex.: backups com falha por situação).
    summary: dict[str, Any] = field(default_factory=dict)
    attempts: int = 1  # aumenta a cada reprocessamento

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionResult:
        """Reconstrói um resultado salvo (``<plataforma>.json``)."""
        return cls(
            platform=data["platform"],
            kind=data["kind"],
            environment=data.get("environment", ""),
            started_at=data.get("started_at") or now_iso(),
            finished_at=data.get("finished_at"),
            datasets={name: list(rows) for name, rows in (data.get("datasets") or {}).items()},
            issues=[Issue(**{**i, "category": IssueCategory(i["category"])}) for i in data.get("issues", [])],
            summary=dict(data.get("summary") or {}),
            attempts=data.get("attempts", 1),
        )

    def add_issue(self, issue: Issue) -> None:
        issue.message = redact(issue.message)
        self.issues.append(issue)
        level = logging.ERROR if issue.severity == ERROR else logging.WARNING
        # A CLI exibe o resumo das falhas; no terminal o log seria duplicado.
        log.log(level, "[%s] %s [%s]: %s", self.platform, issue.stage, issue.category, issue.message, extra=FILE_ONLY)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == ERROR]

    @property
    def status(self) -> str:
        if not self.errors:
            return "sucesso"
        return "parcial" if any(self.datasets.values()) else "falha"

    def counts(self) -> dict[str, int]:
        return {name: len(rows) for name, rows in self.datasets.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "kind": self.kind,
            "environment": self.environment,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "counts": self.counts(),
            "attempts": self.attempts,
            "summary": self.summary,
            "issues": [asdict(i) for i in self.issues],
            "datasets": self.datasets,
        }

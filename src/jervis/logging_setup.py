"""Configuração de logs com redação de segredos em todas as saídas."""

from __future__ import annotations

import contextvars
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from jervis.security import RedactingFormatter

FORMAT = "%(asctime)s %(levelname)-7s [%(run_id)s] %(name)s: %(message)s"

# Execução em andamento: toda linha de log leva o seu identificador (correlação entre logs e resultados).
current_run: contextvars.ContextVar[str] = contextvars.ContextVar("current_run", default="-")


def _add_run_id(record: logging.LogRecord) -> bool:
    record.run_id = current_run.get()
    return True

# Estes loggers registram, em DEBUG, o corpo das requisições ao WebDriver — inclusive o
# texto digitado nos campos, caractere a caractere, o que a redação não consegue mascarar.
# Por isso ficam sempre em WARNING, independentemente do nível escolhido.
_NOISY_LOGGERS = ("selenium", "urllib3", "selenium.webdriver.remote.remote_connection")


# Registros já exibidos ao operador pela CLI vão apenas para o arquivo de log:
# ``log.error(..., extra=FILE_ONLY)``.
FILE_ONLY = {"file_only": True}


def _not_file_only(record: logging.LogRecord) -> bool:
    return not getattr(record, "file_only", False)


def setup_logging(log_file: str | None = None, verbose: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(RedactingFormatter("%(levelname)s: %(message)s"))
    console.addFilter(_not_file_only)
    root.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(RedactingFormatter(FORMAT))
        file_handler.addFilter(_add_run_id)
        root.addHandler(file_handler)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

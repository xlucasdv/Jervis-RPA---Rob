"""Gravação segura de arquivos."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

# No Windows, antivírus e indexação abrem por instantes arquivos recém-gravados, e a troca falha com
# "Acesso negado". Tenta de novo por até ~3 s antes de desistir.
_REPLACE_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.5)


def replace(src: str | Path, dst: str | Path, sleep=time.sleep) -> None:
    for delay in (*_REPLACE_DELAYS, None):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if delay is None or os.name != "nt":
                raise
            sleep(delay)


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> Path:
    """Grava em arquivo temporário e renomeia: quem lê nunca vê um arquivo pela metade."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as fh:
            fh.write(text)
        replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path

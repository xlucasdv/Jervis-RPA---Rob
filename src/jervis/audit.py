"""Trilha de auditoria (Feature 8.4): quem fez o quê, quando e de onde.

Registra coletas (iniciada/concluída, por quem, de qual máquina, quais plataformas e com
qual conta de serviço) e ações administrativas (cadastro de plataformas, credenciais,
agendamentos). Nunca registra senhas ou segredos — usuários de plataforma aparecem mascarados.

O arquivo é encadeado por hash: cada evento guarda o hash do anterior. Alterar ou apagar
uma linha no meio quebra a cadeia, o que ``jervis audit --verify`` detecta.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
from pathlib import Path
from typing import Any

from jervis.collectors.models import now_iso
from jervis.security import redact

GENESIS = "0" * 64


def actor() -> dict[str, str]:
    """Usuário do sistema operacional e máquina que executam a ferramenta."""
    try:
        user = getpass.getuser()
    except Exception:  # sem variável de usuário (ex.: serviço mal configurado)
        user = "desconhecido"
    domain = os.environ.get("USERDOMAIN")
    return {"usuario": f"{domain}\\{user}" if domain and "\\" not in user else user, "maquina": socket.gethostname()}


def _digest(entry: dict[str, Any]) -> str:
    canonical = json.dumps({k: v for k, v in entry.items() if k != "hash"}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, environment: str | None = None):
        self.path = Path(path)
        self.environment = environment

    def record(self, event: str, **details: Any) -> dict[str, Any]:
        """Acrescenta um evento. ``details`` passa pela redação de segredos antes de ser gravado."""
        entry = {
            "em": now_iso(),
            "evento": event,
            **actor(),
            "ambiente": self.environment,
            "detalhes": json.loads(redact(json.dumps(details, ensure_ascii=False, default=str))),
            "hash_anterior": self._last_hash(),
        }
        entry["hash"] = _digest(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def read(self, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return entries[-limit:] if limit else entries

    def verify(self) -> tuple[bool, str]:
        """Confere a cadeia de hashes. Devolve (íntegro, explicação)."""
        if not self.path.exists():
            return True, "Trilha de auditoria vazia."
        previous = GENESIS
        lines = self.path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f"Linha {number} ilegível (arquivo alterado ou corrompido)."
            if entry.get("hash_anterior") != previous:
                return False, f"Linha {number}: cadeia interrompida (evento anterior removido ou alterado)."
            if entry.get("hash") != _digest(entry):
                return False, f"Linha {number}: conteúdo alterado após o registro ({entry.get('evento')} em {entry.get('em')})."
            previous = entry["hash"]
        return True, f"Trilha íntegra: {len(lines)} evento(s) verificados."

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        with open(self.path, "rb") as fh:
            lines = fh.read().splitlines()
        for line in reversed(lines):
            if line.strip():
                try:
                    return json.loads(line)["hash"]
                except (json.JSONDecodeError, KeyError):
                    return GENESIS
        return GENESIS

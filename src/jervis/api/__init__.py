"""Coleta por API (Acronis, Zabbix, Desk Manager): cliente HTTP comum.

Só biblioteca padrão (urllib). Erros viram ``ApiError`` com mensagem para o operador, sem segredos.
"""

from __future__ import annotations

import codecs
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from jervis.errors import JervisError
from jervis.security import redact

DEFAULT_TIMEOUT = 60
_RETRY_STATUS = {429, 502, 503, 504}

# Respostas UTF-8 com um ou outro byte em Latin-1 (visto no Acronis: nome com "ã" numa atividade): o byte inválido
# é lido como Latin-1 em vez de derrubar a leitura da resposta inteira
codecs.register_error("jervis_latin1", lambda err: (err.object[err.start:err.end].decode("latin-1"), err.end))


def decode_body(raw: bytes) -> str:
    return raw.decode("utf-8-sig", errors="jervis_latin1")


class ApiError(JervisError):
    """A plataforma recusou ou não respondeu à chamada de API."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class HttpClient:
    """JSON sobre HTTP, com tempo limite e novas tentativas em falhas transitórias (429/5xx/rede)."""

    def __init__(self, base_url: str, name: str, opener: Callable = urllib.request.urlopen,
                 timeout: int = DEFAULT_TIMEOUT, retries: int = 2, sleep: Callable[[float], None] = time.sleep):
        self.base_url = base_url.rstrip("/")
        self.name = name
        self._open, self.timeout, self.retries, self._sleep = opener, timeout, retries, sleep

    def url(self, path: str, params: dict[str, Any] | None = None) -> str:
        if path.startswith("http"):
            url = path
        else:  # caminho vazio = o próprio endereço base (ex.: .../api_jsonrpc.php do Zabbix)
            url = f"{self.base_url}/{path.lstrip('/')}" if path.strip("/") else self.base_url
        query = {k: v for k, v in (params or {}).items() if v is not None}
        return f"{url}?{urllib.parse.urlencode(query, doseq=True)}" if query else url

    def request(self, method: str, path: str, *, params: dict[str, Any] | None = None, json_body: Any = None,
                form: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> Any:
        body, all_headers = None, {"Accept": "application/json", **(headers or {})}
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            all_headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode("utf-8")
            all_headers["Content-Type"] = "application/x-www-form-urlencoded"
        url = self.url(path, params)
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=body, headers=all_headers, method=method)
            try:
                with self._open(req, timeout=self.timeout) as response:
                    raw = response.read()
                return json.loads(decode_body(raw)) if raw.strip() else None
            except urllib.error.HTTPError as exc:
                detail = _error_detail(exc)
                if exc.code in _RETRY_STATUS and attempt < self.retries:
                    self._sleep(2 * (attempt + 1))
                    continue
                raise ApiError(f"[{self.name}] {method} {path}: HTTP {exc.code}{f' – {detail}' if detail else ''}", exc.code) from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt < self.retries:
                    self._sleep(2 * (attempt + 1))
                    continue
                reason = getattr(exc, "reason", exc)
                raise ApiError(f"[{self.name}] Não foi possível acessar {self.base_url} ({reason}).") from exc
            except json.JSONDecodeError as exc:
                raise ApiError(f"[{self.name}] {method} {path}: resposta não é JSON.") from exc
        raise AssertionError("inalcançável")

    def get(self, path: str, **kwargs) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Any:
        return self.request("POST", path, **kwargs)


def _error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read()[:2000].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - corpo ilegível: segue sem detalhe
        return ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return redact(raw.strip()[:200])
    if isinstance(data, dict):
        for key in ("error_description", "message", "erro", "error", "detail"):
            value = data.get(key)
            if isinstance(value, dict):
                value = value.get("message") or value.get("reason") or json.dumps(value)[:200]
            if value:
                return redact(str(value)[:300])
    return redact(json.dumps(data)[:200])

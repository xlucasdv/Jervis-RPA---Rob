"""API JSON-RPC do Zabbix (token de API).

Docs: https://www.zabbix.com/documentation/current/en/manual/api
O token vai no cabeçalho ``Authorization: Bearer`` (Zabbix 6.4+) ou no campo ``auth`` (versões anteriores).
"""

from __future__ import annotations

import itertools
from typing import Any, Callable
from urllib.parse import urlsplit
import urllib.request

from jervis.api import ApiError, HttpClient
from jervis.security import SecretStr


class ZabbixApi:
    def __init__(self, url: str, token: SecretStr, opener: Callable = urllib.request.urlopen):
        self.http = HttpClient(_api_url(url), "zabbix", opener=opener)
        self._token = token
        self._ids = itertools.count(1)
        self._version: tuple[int, ...] | None = None

    def call(self, method: str, params: Any = None, auth: bool = True) -> Any:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params if params is not None else {},
                                "id": next(self._ids)}
        headers = {}
        if auth:
            if self.version() >= (6, 4):
                headers["Authorization"] = f"Bearer {self._token.reveal()}"
            else:
                body["auth"] = self._token.reveal()
        data = self.http.post("", json_body=body, headers=headers)
        if not isinstance(data, dict):
            raise ApiError(f"[zabbix] {method}: resposta inesperada.")
        if "error" in data:
            err = data["error"]
            raise ApiError(f"[zabbix] {method}: {err.get('message', '')} {err.get('data', '')}".strip())
        return data.get("result")

    def version(self) -> tuple[int, ...]:
        if self._version is None:
            raw = self.call("apiinfo.version", auth=False)
            self._version = tuple(int(p) for p in str(raw).split(".")[:2] if p.isdigit())
        return self._version

    def check(self) -> str:
        hosts = self.call("host.get", {"countOutput": True})
        groups = self.call("hostgroup.get", {"countOutput": True})
        return f"Zabbix {'.'.join(map(str, self.version()))}; {hosts} host(s) em {groups} grupo(s)"

    def customer_names(self) -> list[str]:
        """Grupos de hosts que têm hosts (no Zabbix, cada cliente é um grupo de hosts)."""
        groups = self.call("hostgroup.get", {"output": ["name"], "with_hosts": True})
        return sorted({(g.get("name") or "").strip() for g in groups} - {""}, key=str.lower)


def _api_url(url: str) -> str:
    """https://zabbix.empresa/index.php → https://zabbix.empresa/api_jsonrpc.php (mantém subdiretório)."""
    parts = urlsplit(url)
    path = parts.path
    if not path.endswith("api_jsonrpc.php"):
        path = path.rsplit("/", 1)[0] if path.endswith(".php") else path.rstrip("/")
        path = f"{path}/api_jsonrpc.php"
    return f"{parts.scheme}://{parts.netloc}{path}"

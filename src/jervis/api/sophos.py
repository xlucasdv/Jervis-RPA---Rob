"""API do Sophos Central (credencial de API OAuth2, client_credentials).

Docs: https://developer.sophos.com/getting-started

O token sai de id.sophos.com; o ``whoami`` diz o tipo da conta (partner, organization ou tenant) e onde ficam os
dados. Numa conta de parceiro, os clientes são os tenants (``/partner/v1/tenants``) e cada chamada de dados vai ao
``apiHost`` do tenant com o cabeçalho ``X-Tenant-ID``.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterator
import urllib.request

from jervis.api import ApiError, HttpClient
from jervis.security import SecretStr

TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
GLOBAL_URL = "https://api.central.sophos.com"
MAX_PAGES = 500
_LIST_HEADER = {"partner": "X-Partner-ID", "organization": "X-Organization-ID"}


class SophosApi:
    def __init__(self, base_url: str, client_id: SecretStr, client_secret: SecretStr,
                 opener: Callable = urllib.request.urlopen, clock: Callable[[], float] = time.monotonic):
        self.http = HttpClient((base_url or GLOBAL_URL).rstrip("/"), "sophos", opener=opener)
        self._client_id, self._secret, self._clock = client_id, client_secret, clock
        self._token: str | None = None
        self._expires = 0.0
        self._whoami: dict[str, Any] | None = None

    # --- autenticação ------------------------------------------------------------

    def _auth(self) -> dict[str, str]:
        if not self._token or self._clock() >= self._expires:
            data = self.http.post(TOKEN_URL, form={"grant_type": "client_credentials", "client_id": self._client_id.reveal(),
                                                   "client_secret": self._secret.reveal(), "scope": "token"})
            if not isinstance(data, dict) or "access_token" not in data:
                raise ApiError("[sophos] O login não devolveu um token.")
            self._token = SecretStr(data["access_token"]).reveal()  # registrado para não aparecer em logs
            self._expires = self._clock() + max(int(data.get("expires_in", 3600)) - 120, 60)
        return {"Authorization": f"Bearer {self._token}"}

    def whoami(self) -> dict[str, Any]:
        """{'id': ..., 'idType': 'partner' | 'organization' | 'tenant', 'apiHosts': {'global': ..., 'dataRegion': ...}}"""
        if self._whoami is None:
            data = self.http.get(f"{self.http.base_url}/whoami/v1", headers=self._auth())
            if not isinstance(data, dict) or not data.get("id") or not data.get("idType"):
                raise ApiError("[sophos] whoami não identificou a conta da credencial.")
            self._whoami = data
        return self._whoami

    # --- clientes (tenants) -------------------------------------------------------

    def tenants(self) -> list[dict[str, Any]]:
        """Tenants que a credencial enxerga: os clientes do parceiro/organização, ou o próprio tenant."""
        me = self.whoami()
        kind = me["idType"]
        if kind == "tenant":
            return [{"id": me["id"], "name": me.get("name") or me["id"], "apiHost": (me.get("apiHosts") or {}).get("dataRegion")}]
        if kind not in _LIST_HEADER:
            raise ApiError(f"[sophos] Tipo de conta não suportado: {kind}.")
        host = (me.get("apiHosts") or {}).get("global") or self.http.base_url
        headers = {**self._auth(), _LIST_HEADER[kind]: me["id"]}
        items, page, total = [], 1, 1
        while page <= total and page <= MAX_PAGES:
            data = self.http.get(f"{host}/{kind}/v1/tenants", params={"page": page, "pageTotal": "true" if page == 1 else None},
                                 headers=headers) or {}
            items += data.get("items") or []
            if page == 1:
                total = int((data.get("pages") or {}).get("total") or 1)
            page += 1
        return items

    def customer_names(self) -> list[str]:
        return sorted({(t.get("name") or "").strip() for t in self.tenants()} - {""}, key=str.lower)

    def customer_tenant(self, name: str) -> dict[str, Any]:
        """Tenant do cliente pelo nome exibido no Sophos Central (sem diferenciar maiúsculas)."""
        tenants = self.tenants()
        found = [t for t in tenants if (t.get("name") or "").strip().lower() == name.strip().lower()]
        if len(found) == 1:
            if not found[0].get("apiHost"):
                raise ApiError(f"[sophos] O tenant '{name}' não informa o endereço dos dados (apiHost).")
            return found[0]
        if found:
            raise ApiError(f"[sophos] Há {len(found)} clientes chamados '{name}' no Sophos Central.")
        similar = [t["name"] for t in tenants if name.strip().lower()[:4] in (t.get("name") or "").lower()]
        raise ApiError(f"[sophos] Cliente '{name}' não encontrado no Sophos Central."
                       + (f" Parecidos: {', '.join(similar)}." if similar else "")
                       + " Ajuste o nome com 'jervis customers link ... --external-name'.")

    def check(self) -> str:
        me = self.whoami()
        if me["idType"] == "tenant":
            return f"conta 'tenant' ({me['id']}); dados em {(me.get('apiHosts') or {}).get('dataRegion')}"
        return f"conta '{me['idType']}' ({me['id']}); {len(self.tenants())} cliente(s) (tenants)"

    # --- dados de um cliente --------------------------------------------------------

    def _pages(self, tenant: dict[str, Any], path: str, **params) -> Iterator[dict[str, Any]]:
        """Itens de todas as páginas (cursor ``pages.nextKey``) de uma rota do tenant."""
        url = f"{tenant['apiHost'].rstrip('/')}/{path.lstrip('/')}"
        key = None
        for _ in range(MAX_PAGES):
            data = self.http.get(url, params={**params, "pageFromKey": key},
                                 headers={**self._auth(), "X-Tenant-ID": tenant["id"]}) or {}
            yield from data.get("items") or []
            next_key = (data.get("pages") or {}).get("nextKey")
            if not next_key or next_key == key or not data.get("items"):
                return
            key = next_key
        raise ApiError(f"[sophos] {path}: mais de {MAX_PAGES} páginas; coleta interrompida.")

    def endpoints(self, tenant: dict[str, Any]) -> list[dict[str, Any]]:
        return list(self._pages(tenant, "/endpoint/v1/endpoints", view="full"))

    def alerts(self, tenant: dict[str, Any], since: datetime, until: datetime) -> list[dict[str, Any]]:
        def utc(moment):
            return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return list(self._pages(tenant, "/common/v1/alerts", **{"from": utc(since), "to": utc(until)}))

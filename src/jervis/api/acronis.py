"""API do Acronis Cyber Protect Cloud (cliente de API OAuth2, client_credentials).

Docs: https://developer.acronis.com/doc/

O cliente de API pertence ao parceiro (Contego). Alertas aceitam filtro pelo locatário do cliente; máquinas e
atividades exigem um token restrito ao cliente, obtido trocando o token do parceiro (jwt-bearer + escopo
``urn:acronis.com:tenant-id:<uuid>``).
"""

from __future__ import annotations

import base64
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit
import urllib.request

from jervis.api import ApiError, HttpClient
from jervis.security import SecretStr

_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
MAX_PAGES = 200


class AcronisApi:
    def __init__(self, base_url: str, client_id: SecretStr, client_secret: SecretStr,
                 opener: Callable = urllib.request.urlopen, clock: Callable[[], float] = time.monotonic):
        self.http = HttpClient(_datacenter(base_url), "acronis", opener=opener)
        self._client_id, self._secret, self._clock = client_id, client_secret, clock
        self._token: str | None = None
        self._expires = 0.0

    # --- autenticação ------------------------------------------------------------

    def _auth(self) -> dict[str, str]:
        if not self._token or self._clock() >= self._expires:
            basic = base64.b64encode(f"{self._client_id.reveal()}:{self._secret.reveal()}".encode()).decode()
            data = self.http.post("/api/2/idp/token", form={"grant_type": "client_credentials"},
                                  headers={"Authorization": f"Basic {basic}"})
            self._token, self._expires = self._accept_token(data)
        return {"Authorization": f"Bearer {self._token}"}

    def _accept_token(self, data: Any) -> tuple[str, float]:
        if not isinstance(data, dict) or "access_token" not in data:
            raise ApiError("[acronis] O login não devolveu um token.")
        token = SecretStr(data["access_token"]).reveal()  # registrado para não aparecer em logs
        return token, self._clock() + max(int(data.get("expires_in", 3600)) - 120, 60)

    def get(self, path: str, **params) -> Any:
        return self.http.get(path, params=params, headers=self._auth())

    def pages(self, path: str, headers: dict[str, str] | None = None, cursor_only: bool = False,
              **params) -> Iterator[dict[str, Any]]:
        """Itens de todas as páginas (cursor ``paging.cursors.after``).

        ``cursor_only``: nas páginas seguintes envia só o cursor (a API de tarefas recusa filtros junto com ``after``).
        """
        after = None
        for _ in range(MAX_PAGES):
            query = {"after": after, "limit": params.get("limit")} if after and cursor_only else {**params, "after": after}
            data = self.http.get(path, params=query, headers=headers or self._auth()) or {}
            yield from data.get("items", [])
            next_after = ((data.get("paging") or {}).get("cursors") or {}).get("after")
            if not next_after or next_after == after or not data.get("items"):
                return
            after = next_after
        raise ApiError(f"[acronis] {path}: mais de {MAX_PAGES} páginas; coleta interrompida.")

    # --- conta ----------------------------------------------------------------------

    def tenant_id(self) -> str:
        """Locatário (parceiro) dono do cliente de API."""
        data = self.get(f"/api/2/clients/{self._client_id.reveal()}")
        tenant = (data or {}).get("tenant_id")
        if not tenant:
            raise ApiError("[acronis] Não foi possível descobrir o locatário do cliente de API.")
        return tenant

    def tenant(self, tenant_id: str) -> dict[str, Any]:
        return self.get(f"/api/2/tenants/{tenant_id}")

    def child_tenants(self, tenant_id: str) -> list[dict[str, Any]]:
        """Locatários filhos (os clientes do parceiro), com nome e tipo."""
        ids = (self.get(f"/api/2/tenants/{tenant_id}/children") or {}).get("items", [])
        tenants: list[dict[str, Any]] = []
        for start in range(0, len(ids), 100):
            tenants += (self.get("/api/2/tenants", uuids=",".join(ids[start:start + 100])) or {}).get("items", [])
        return tenants

    def customers(self) -> list[dict[str, Any]]:
        """Locatários do tipo cliente logo abaixo da conta de parceiro."""
        return [t for t in self.child_tenants(self.tenant_id()) if t.get("kind") == "customer"]

    def customer_names(self) -> list[str]:
        return sorted({(t.get("name") or "").strip() for t in self.customers()} - {""}, key=str.lower)

    def customer_tenant(self, name: str) -> dict[str, Any]:
        """Locatário do cliente pelo nome exibido no Acronis (sem diferenciar maiúsculas)."""
        customers = self.customers()
        found = [t for t in customers if (t.get("name") or "").strip().lower() == name.strip().lower()]
        if len(found) == 1:
            return found[0]
        if found:
            raise ApiError(f"[acronis] Há {len(found)} clientes chamados '{name}' no Acronis.")
        similar = [t["name"] for t in customers if name.strip().lower()[:4] in (t.get("name") or "").lower()]
        raise ApiError(f"[acronis] Cliente '{name}' não encontrado no Acronis."
                       + (f" Parecidos: {', '.join(similar)}." if similar else "")
                       + " Ajuste o nome com 'jervis customers link ... --external-name'.")

    def check(self) -> str:
        tenant = self.tenant(self.tenant_id())
        children = self.child_tenants(tenant["id"])
        customers = [t for t in children if t.get("kind") == "customer"]
        return (f"locatário '{tenant.get('name')}' ({tenant.get('kind')}); "
                f"{len(customers)} cliente(s) e {len(children) - len(customers)} outro(s) locatário(s) abaixo dele")

    # --- dados de um cliente --------------------------------------------------------

    def for_customer(self, tenant_uuid: str) -> CustomerSession:
        return CustomerSession(self, tenant_uuid)

    def alerts(self, tenant_uuid: str) -> list[dict[str, Any]]:
        return list(self.pages("/api/alert_manager/v1/alerts", tenant=tenant_uuid, limit=500))


class CustomerSession:
    """Chamadas com token restrito ao locatário do cliente (máquinas, atividades)."""

    def __init__(self, api: AcronisApi, tenant_uuid: str):
        self.api, self.tenant_uuid = api, tenant_uuid
        self._token: str | None = None
        self._expires = 0.0

    def _auth(self) -> dict[str, str]:
        if not self._token or self.api._clock() >= self._expires:
            partner = self.api._auth()["Authorization"].split(" ", 1)[1]
            data = self.api.http.post("/api/2/idp/token", form={
                "grant_type": _TOKEN_EXCHANGE, "assertion": partner, "scope": f"urn:acronis.com:tenant-id:{self.tenant_uuid}"})
            self._token, self._expires = self.api._accept_token(data)
        return {"Authorization": f"Bearer {self._token}"}

    def machines(self) -> list[dict[str, Any]]:
        return list(self.api.pages("/api/resource_management/v4/resource_statuses", headers=self._auth(),
                                   type="resource.machine", include_attributes="true", limit=500))

    def activities(self, since_iso: str) -> list[dict[str, Any]]:
        return list(self.api.pages("/api/task_manager/v2/activities", headers=self._auth(), cursor_only=True,
                                   createdAt=f"gt({since_iso})", order="desc(createdAt)", limit=500))

    # --- API interna do console (painel "Visão geral") ------------------------------
    # NÃO DOCUMENTADA pela Acronis: são as rotas que o próprio console usa nos widgets do painel
    # (definidas em assets/configs/widgets.config.json da interface). Podem mudar sem aviso em qualquer
    # atualização da Acronis; por isso cada leitura é isolada e uma falha vira aviso, nunca interrompe a coleta.

    INTERNAL_PREFIX = "/bc/api/monitoring/api/1/playbook/call"

    def playbook(self, name: str, **params) -> dict[str, Any]:
        return self.api.http.get(f"{self.INTERNAL_PREFIX}/{name}", params={"_lang": "pt", **params},
                                 headers=self._auth()) or {}

    def _series(self, name: str, index: int = 0, **params) -> list[dict[str, Any]]:
        series = self.playbook(name, **params).get("series") or []
        return (series[index].get("data") or []) if len(series) > index else []

    def protection_status(self) -> dict[str, int]:
        """Gerenciados/descobertos e protegidos/desprotegidos (widget "Status de proteção")."""
        counts: dict[str, int] = {}
        for serie in self.playbook("protection_status").get("series") or []:
            for item in serie.get("data") or []:
                counts[item["category"]] = int(item.get("count") or 0)
        return counts

    def threat_status(self) -> dict[str, int]:
        """Ameaças mitigadas automática/manualmente e não mitigadas (widget "Status da ameaça").
        A rota ignora o período: é a situação atual do painel."""
        return {i["category"]: int(i.get("count") or 0) for i in self._series("edr/threat_status")}

    def tactics(self, since: int, until: int) -> list[dict[str, Any]]:
        """Detecções por tática MITRE ATT&CK no período, com o período anterior (widget "Detecção por táticas")."""
        return self._series("edr/detection_by_tactics", **{"from": since, "to": until})

    def vulnerable_machines(self) -> dict[str, int]:
        """Máquinas por nível de vulnerabilidade (widget "Máquinas vulneráveis")."""
        return {i.get("va_severity") or i.get("category"): int(i.get("resource_count") or i.get("count") or 0)
                for i in self._series("vulnerabilities_pie")}

    def vulnerabilities(self, limit: int = 50000) -> list[dict[str, Any]]:
        """Vulnerabilidades existentes: máquina, fornecedor, produto, versão, CVE, score e severidade."""
        return self._series("existing_vulnerabilities", limit=limit)

    def missing_updates(self) -> dict[str, int]:
        return {i["category"]: int(i.get("count") or 0) for i in self._series("missing_updates")}

    def patch_installs(self, since: int, until: int) -> dict[str, Any]:
        """Instalação de patches no período: máquinas por status e quantidade de atualizações por status."""
        by_status = {i["status"]: int(i.get("count") or 0) for i in self._series("patch_install_status", **{"from": since, "to": until})}
        updates = {i["installation_status"]: int(i.get("updates_total_number") or 0)
                   for i in self._series("patch_install_sum", **{"from": since, "to": until})}
        return {"maquinas": by_status, "atualizacoes": updates}

    def protection_summary(self, since: int, until: int) -> dict[str, Any]:
        """Resumo do período (widget "Resumo da Cyber Protection"): URLs maliciosas e periféricos bloqueados,
        ameaças mitigadas, patches instalados e vulnerabilidades corrigidas."""
        data = self._series("cyber_protection_summary", **{"from": since, "to": until})
        return data[0] if data else {}

    def remote_sessions(self, since: int, until: int) -> list[dict[str, Any]]:
        return self._series("remote_session_history", **{"from": since, "to": until, "limit": 10000})

    def incidents(self) -> list[dict[str, Any]]:
        """Incidentes do EDR (API pública /api/mdr/v1), todos; o período é filtrado por quem chama."""
        items, cursor = [], None
        for _ in range(MAX_PAGES):
            data = self.api.http.get("/api/mdr/v1/incidents", params={"customer_id": self.tenant_uuid, "limit": 200,
                                                                       "cursor": cursor}, headers=self.api._auth()) or {}
            items += data.get("items") or []
            cursor = data.get("cursor")
            if not cursor or not data.get("items"):
                return items
        raise ApiError(f"[acronis] incidentes do EDR: mais de {MAX_PAGES} páginas; coleta interrompida.")


def _datacenter(url: str) -> str:
    """https://br02-cloud.acronis.com/login → https://br02-cloud.acronis.com"""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"

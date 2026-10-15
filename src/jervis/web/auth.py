"""Login com a conta Microsoft 365 (Entra ID, OpenID Connect com PKCE) pela biblioteca oficial MSAL.

Só pede a identificação da pessoa (openid/profile): o Jervis não recebe acesso a e-mail, arquivos ou Teams.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from jervis.errors import JervisError


class AuthError(JervisError):
    """O login na Microsoft não foi concluído."""


@dataclass
class Identity:
    email: str
    name: str
    oid: str | None


class EntraAuth:
    def __init__(self, tenant_id: str, client_id: str, client_secret: Callable[[], str | None], redirect_uri: str,
                 app_factory: Callable[..., Any] | None = None):
        self.tenant_id, self.client_id, self.redirect_uri = tenant_id, client_id, redirect_uri
        self._secret, self._factory, self._app = client_secret, app_factory, None

    def _client(self):
        # Criado no primeiro login: a MSAL consulta o Entra ID ao ser criada (o servidor sobe mesmo sem internet)
        if self._app is None:
            secret = self._secret()
            if not secret:
                raise AuthError("Segredo do aplicativo no Entra ID não cadastrado: rode 'jervis web set-secret'.")
            if self._factory is None:
                import msal

                self._factory = msal.ConfidentialClientApplication
            self._app = self._factory(self.client_id, client_credential=secret,
                                      authority=f"https://login.microsoftonline.com/{self.tenant_id}")
        return self._app

    def begin(self) -> dict[str, Any]:
        """Início do login: devolve o fluxo (guardar na sessão) com o endereço da Microsoft em ``auth_uri``."""
        return self._client().initiate_auth_code_flow(scopes=[], redirect_uri=self.redirect_uri, prompt="select_account")

    def finish(self, flow: dict[str, Any], params: dict[str, str]) -> Identity:
        """Volta da Microsoft: confere estado, PKCE e nonce (MSAL) e a organização da conta."""
        try:
            result = self._client().acquire_token_by_auth_code_flow(flow, params)
        except ValueError as exc:  # estado diferente do iniciado (login antigo, outra aba, tentativa forjada)
            raise AuthError("Login expirado ou iniciado em outra janela. Entre de novo.") from exc
        if "error" in result:
            raise AuthError(f"A Microsoft recusou o login: {result.get('error_description') or result['error']}")
        claims = result.get("id_token_claims") or {}
        if (claims.get("tid") or "").lower() != self.tenant_id:
            raise AuthError("Essa conta é de outra organização.")
        email = (claims.get("preferred_username") or claims.get("email") or "").strip().lower()
        if not email:
            raise AuthError("A Microsoft não informou o e-mail da conta.")
        return Identity(email=email, name=claims.get("name") or email, oid=claims.get("oid"))

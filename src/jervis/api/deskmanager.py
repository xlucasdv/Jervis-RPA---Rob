"""API do Desk Manager (https://api.desk.ms).

Login: POST /Login/autenticar com a chave do Operador no cabeçalho Authorization e a chave do Ambiente no
corpo ({"PublicKey": ...}); a resposta é o token de sessão, usado depois no cabeçalho Authorization.
"""

from __future__ import annotations

from typing import Any, Callable
import urllib.request

from jervis.api import ApiError, HttpClient
from jervis.security import SecretStr

DEFAULT_URL = "https://api.desk.ms"


class DeskManagerApi:
    def __init__(self, url: str, operator_key: SecretStr, environment_key: SecretStr,
                 opener: Callable = urllib.request.urlopen):
        self.http = HttpClient(url or DEFAULT_URL, "deskmanager", opener=opener)
        self._operator, self._environment = operator_key, environment_key
        self._token: str | None = None

    def _auth(self) -> dict[str, str]:
        if not self._token:
            data = self.http.post("/Login/autenticar", json_body={"PublicKey": self._environment.reveal()},
                                  headers={"Authorization": self._operator.reveal()})
            token = data if isinstance(data, str) else (data or {}).get("access_token") if isinstance(data, dict) else None
            # Em caso de erro, a API devolve uma frase (ex.: "Está faltando a chave do Operador") no lugar do token.
            if not token or " " in token or len(token) < 16:
                raise ApiError(f"[deskmanager] Login recusado: {data if isinstance(data, str) else 'resposta inesperada'}")
            self._token = SecretStr(token).reveal()
        return {"Authorization": self._token}

    def post(self, path: str, body: Any = None) -> Any:
        data = self.http.post(path, json_body=body if body is not None else {}, headers=self._auth())
        if isinstance(data, dict) and data.get("erro"):
            raise ApiError(f"[deskmanager] {path}: {data['erro']}")
        return data

    def check(self) -> str:
        self._auth()
        return "login OK"

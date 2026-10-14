"""Clientes de API (Acronis, Zabbix, Desk Manager) com respostas simuladas."""

import base64
import io
import json
import urllib.error

import pytest

from jervis.api import ApiError, HttpClient, credentials as api_credentials
from jervis.api.acronis import AcronisApi
from jervis.api.deskmanager import DeskManagerApi
from jervis.api.zabbix import ZabbixApi, _api_url
from jervis.credentials import CredentialStore
from jervis.errors import CredentialError
from jervis.security import SecretStr


class FakeApi:
    """Servidor falso: (método, caminho sem query) → resposta (objeto JSON, ou exceção)."""

    def __init__(self, routes):
        self.routes, self.requests = routes, []

    def __call__(self, request, timeout=None):
        path = request.full_url.split("?")[0]
        self.requests.append({"method": request.get_method(), "url": request.full_url, "path": path,
                              "headers": {k.lower(): v for k, v in request.header_items()},
                              "body": request.data.decode() if request.data else None})
        for (method, suffix), answer in self.routes.items():
            if request.get_method() == method and path.endswith(suffix):
                answer = answer(self.requests[-1]) if callable(answer) else answer
                if isinstance(answer, Exception):
                    raise answer
                return io.BytesIO(json.dumps(answer).encode())
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"message": "rota inexistente"}'))


def secret(value):
    return SecretStr(value)


# --- HTTP comum -----------------------------------------------------------------------


def test_http_retries_transient_errors_then_reports_status():
    calls = []

    def flaky(request, timeout=None):
        calls.append(1)
        raise urllib.error.HTTPError(request.full_url, 503, "Unavailable", {}, io.BytesIO(b'{"message": "manutencao"}'))

    client = HttpClient("https://x.example.com", "teste", opener=flaky, retries=2, sleep=lambda s: None)
    with pytest.raises(ApiError, match="HTTP 503 – manutencao") as info:
        client.get("/coisa")
    assert info.value.status == 503 and len(calls) == 3


def test_http_reads_stray_latin1_bytes_in_utf8_response():
    raw = '{"items": [{"resource": "PC-JOÃO", "user": "'.encode() + "joão".encode("latin-1") + b'"}]}'
    client = HttpClient("https://x.example.com", "teste", opener=lambda request, timeout=None: io.BytesIO(raw))
    assert client.get("/coisa") == {"items": [{"resource": "PC-JOÃO", "user": "joão"}]}


# --- Acronis --------------------------------------------------------------------------


def acronis_routes(token_calls):
    def token(req):
        token_calls.append(req)
        return {"access_token": "tok-123", "expires_in": 7200}
    return {
        ("POST", "/api/2/idp/token"): token,
        ("GET", "/api/2/clients/cid"): {"tenant_id": "partner-1"},
        ("GET", "/api/2/tenants/partner-1"): {"id": "partner-1", "name": "Contego Security", "kind": "partner"},
        ("GET", "/api/2/tenants/partner-1/children"): {"items": ["c1", "c2", "f1"]},
        ("GET", "/api/2/tenants"): {"items": [{"id": "c1", "name": "MERCOS", "kind": "customer"},
                                              {"id": "c2", "name": "Passebus", "kind": "customer"},
                                              {"id": "f1", "name": "Pasta", "kind": "folder"}]},
    }


def test_acronis_login_once_and_check():
    token_calls = []
    fake = FakeApi(acronis_routes(token_calls))
    api = AcronisApi("https://br02-cloud.acronis.com/login", secret("cid"), secret("s3cr3t"), opener=fake)
    assert api.check() == "locatário 'Contego Security' (partner); 2 cliente(s) e 1 outro(s) locatário(s) abaixo dele"
    assert len(token_calls) == 1  # token reaproveitado
    login = token_calls[0]
    assert login["headers"]["authorization"] == "Basic " + base64.b64encode(b"cid:s3cr3t").decode()
    assert login["body"] == "grant_type=client_credentials"
    assert fake.requests[1]["url"].startswith("https://br02-cloud.acronis.com/api/2/clients/cid")
    assert fake.requests[1]["headers"]["authorization"] == "Bearer tok-123"
    assert "uuids=c1%2Cc2%2Cf1" in fake.requests[-1]["url"]


def test_acronis_rejected_client():
    fake = FakeApi({("POST", "/api/2/idp/token"): urllib.error.HTTPError(
        "u", 401, "Unauthorized", {}, io.BytesIO(b'{"error": "invalid_client", "error_description": "Client authentication failed"}'))})
    api = AcronisApi("https://br02-cloud.acronis.com", secret("cid"), secret("errado"), opener=fake)
    with pytest.raises(ApiError, match="HTTP 401 – Client authentication failed") as info:
        api.check()
    assert "errado" not in str(info.value)


# --- Zabbix ---------------------------------------------------------------------------


@pytest.mark.parametrize("url, expected", [
    ("https://z.example.com/index.php", "https://z.example.com/api_jsonrpc.php"),
    ("https://z.example.com/zabbix/index.php", "https://z.example.com/zabbix/api_jsonrpc.php"),
    ("https://z.example.com/zabbix/", "https://z.example.com/zabbix/api_jsonrpc.php"),
    ("https://z.example.com/api_jsonrpc.php", "https://z.example.com/api_jsonrpc.php"),
])
def test_zabbix_api_url(url, expected):
    assert _api_url(url) == expected


def zabbix_server(version):
    def handler(req):
        body = json.loads(req["body"])
        results = {"apiinfo.version": version, "host.get": "42", "hostgroup.get": "7"}
        return {"jsonrpc": "2.0", "result": results[body["method"]], "id": body["id"]}
    return FakeApi({("POST", "/api_jsonrpc.php"): handler})


def test_zabbix_new_versions_use_bearer_header():
    fake = zabbix_server("7.0.4")
    assert ZabbixApi("https://z.example.com/index.php", secret("tok"), opener=fake).check() == "Zabbix 7.0; 42 host(s) em 7 grupo(s)"
    host_get = fake.requests[1]
    assert host_get["headers"]["authorization"] == "Bearer tok" and "auth" not in json.loads(host_get["body"])
    assert "authorization" not in fake.requests[0]["headers"]  # apiinfo.version não leva token


def test_zabbix_old_versions_send_auth_in_body():
    fake = zabbix_server("6.0.20")
    ZabbixApi("https://z.example.com", secret("tok"), opener=fake).check()
    assert json.loads(fake.requests[1]["body"])["auth"] == "tok"


def test_zabbix_api_error():
    fake = FakeApi({("POST", "/api_jsonrpc.php"): lambda req: (
        {"jsonrpc": "2.0", "result": "7.0.0", "id": 1} if "apiinfo" in req["body"] else
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params.", "data": "Not authorised."}, "id": 2})})
    with pytest.raises(ApiError, match="host.get: Invalid params. Not authorised."):
        ZabbixApi("https://z.example.com", secret("tok"), opener=fake).check()


# --- Desk Manager ---------------------------------------------------------------------


def test_deskmanager_login_and_token_header():
    fake = FakeApi({("POST", "/Login/autenticar"): "a1b2c3d4e5f6a7b8c9d0e1f2",
                    ("POST", "/Clientes/lista"): {"root": []}})
    api = DeskManagerApi("https://api.desk.ms", secret("chave-operador"), secret("chave-ambiente"), opener=fake)
    assert api.post("/Clientes/lista") == {"root": []}
    login, call = fake.requests
    assert login["headers"]["authorization"] == "chave-operador" and json.loads(login["body"]) == {"PublicKey": "chave-ambiente"}
    assert call["headers"]["authorization"] == "a1b2c3d4e5f6a7b8c9d0e1f2"


def test_deskmanager_rejected_login_message():
    fake = FakeApi({("POST", "/Login/autenticar"): "Está faltando a chave do Operador"})
    with pytest.raises(ApiError, match="Login recusado: Está faltando a chave do Operador"):
        DeskManagerApi("https://api.desk.ms", secret("x"), secret("y"), opener=fake).check()


def test_deskmanager_error_payload():
    fake = FakeApi({("POST", "/Login/autenticar"): "a1b2c3d4e5f6a7b8c9d0e1f2",
                    ("POST", "/Clientes/lista"): {"erro": "Token expirado ou não existe"}})
    with pytest.raises(ApiError, match="Token expirado"):
        DeskManagerApi("", secret("x"), secret("y"), opener=fake).post("/Clientes/lista")


# --- credenciais de API ---------------------------------------------------------------


def test_api_credentials_vault_and_env(memory_keyring):
    store = CredentialStore("jervis3000-teste")
    with pytest.raises(CredentialError, match="falta: Client ID do cliente de API, Client secret"):
        api_credentials.load(store, "acronis", "acronis", environ={})
    api_credentials.save(store, "acronis", "acronis", {"client_id": "cid", "client_secret": "s3"})
    creds = api_credentials.load(store, "acronis", "acronis", environ={})
    assert creds["client_id"].reveal() == "cid" and str(creds["client_secret"]) != "s3"
    env = {api_credentials.env_name("acronis", "client_secret"): "da-variavel"}
    assert api_credentials.load(store, "acronis", "acronis", environ=env)["client_secret"].reveal() == "da-variavel"
    with pytest.raises(CredentialError, match="não tem acesso por API"):
        api_credentials.fields_for("pacote.modulo.Classe")

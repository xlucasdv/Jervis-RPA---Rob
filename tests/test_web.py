"""Interface web: rede permitida, login Microsoft 365, perfis, proteção contra requisições forjadas e arquivos."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from jervis.config import AppConfig, DatabaseConfig, Settings, WebConfig, parse_config
from jervis.credentials import CredentialStore
from jervis.db import repository
from jervis.db.repository import CustomerReport, RecordError, WebUser
from jervis.errors import ConfigError
from jervis.web import certs, create_app
from jervis.web.auth import AuthError, EntraAuth, Identity
from jervis.web.jobs import DONE, FAILED, Jobs

TENANT, CLIENT = "11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000"
LAN = {"REMOTE_ADDR": "192.168.0.10"}


class FakeConn:
    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class FakeAuth:
    def __init__(self):
        self.identity = Identity("ana@contego.com.br", "Ana Souza", "oid-ana")
        self.error = None

    def begin(self):
        return {"auth_uri": "https://login.microsoftonline.com/authorize?x=1", "state": "s1"}

    def finish(self, flow, params):
        assert flow["state"] == "s1" and params["state"] == "s1"
        if self.error:
            raise AuthError(self.error)
        return self.identity


class FakeRepo:
    """Banco em memória com as funções do repositório que a interface usa."""

    def __init__(self, output: Path):
        self.users = {1: WebUser(1, "ana@contego.com.br", "Ana Souza", "revisor", True, None, None),
                      2: WebUser(2, "bruno@contego.com.br", "Bruno", "leitura", True, None, None),
                      3: WebUser(3, "carla@contego.com.br", "Carla", "admin", True, None, None)}
        run = output / "clientes" / "alfa" / "20261014-100000"
        run.mkdir(parents=True)
        (run / "cliente.json").write_text(json.dumps({"servicos": {"acronis": "ALFA", "sophos": "Alfa SA"}}), encoding="utf-8")
        (run / "acronis.json").write_text(json.dumps({"platform": "acronis", "status": "sucesso", "counts": {"maquinas": 7},
                                                      "issues": [], "datasets": {"maquinas": [{"x": 1}] * 50}}), encoding="utf-8")
        (run / "sophos.json").write_text(json.dumps({"platform": "sophos", "status": "falha", "counts": {},
                                                     "issues": [{"severity": "erro", "message": "Há 2 tenants"}]}), encoding="utf-8")
        (run / "relatorio_executivo.pdf").write_bytes(b"%PDF-1.4 exec")
        (run / "relatorio_mensal.xlsx").write_bytes(b"PK xlsx")
        (run / "consolidado.json").write_text("{}", encoding="utf-8")
        when = datetime(2026, 10, 14, 13, 0)
        self.reports = {
            10: CustomerReport(10, 5, "Alfa", "2026-09", "Setembro de 2026", str(run), "parcial", "pendente",
                               "agendamento:fechamento_mensal", "CONTEGO\\svc", when),
            11: CustomerReport(11, 6, "Beta", "2026-09", "Setembro de 2026", None, "falha", "falha", "manual", None, when,
                               observacao="[sophos] Cliente não encontrado"),
            12: CustomerReport(12, 7, "Gama", "2026-09", "Setembro de 2026", "C:\\Windows", "sucesso", "pendente", "manual", None, when),
            13: CustomerReport(13, 5, "Alfa", "2026-09", "Setembro de 2026", str(run), "parcial", "substituido", "manual", None, when),
        }
        self.reviews, self.logins, self.reopened = [], [], []

    def install(self, monkeypatch):
        monkeypatch.setattr(repository, "get_web_user", lambda conn, uid: self.users.get(uid))
        monkeypatch.setattr(repository, "find_web_user",
                            lambda conn, email: next((u for u in self.users.values() if u.email == email), None))
        monkeypatch.setattr(repository, "list_web_users", lambda conn: list(self.users.values()))
        monkeypatch.setattr(repository, "record_web_login", lambda conn, uid, oid, name: self.logins.append((uid, oid, name)))
        monkeypatch.setattr(repository, "list_reports", lambda conn, status, month: list(self.reports.values()))
        monkeypatch.setattr(repository, "list_competencias", lambda conn: ["2026-09"])
        monkeypatch.setattr(repository, "find_report", self.find_report)
        monkeypatch.setattr(repository, "review_report", self.review_report)
        monkeypatch.setattr(repository, "reopen_report", lambda conn, rid: self.reopened.append(rid))

    def find_report(self, conn, ref, competencia=None):
        report = self.reports.get(int(ref.lstrip("#")))
        if not report:
            raise RecordError(f"Relatório {ref} não encontrado.")
        return report

    def review_report(self, conn, rid, status, reviewer, note=None):
        if self.reports[rid].status != "pendente":
            raise RecordError(f"O relatório #{rid} não está pendente de revisão.")
        self.reports[rid].status = status
        self.reviews.append((rid, status, reviewer, note))


@pytest.fixture
def env(monkeypatch, tmp_path):
    output = tmp_path / "output"
    config = AppConfig(settings=Settings(output_dir=str(output), audit_file=str(tmp_path / "auditoria.jsonl")), platforms={},
                       web=WebConfig(public_url="https://jervis.local:8443", tenant_id=TENANT, client_id=CLIENT),
                       database=DatabaseConfig())
    repo, auth = FakeRepo(output), FakeAuth()
    repo.install(monkeypatch)
    submitted = []
    jobs = Jobs(lambda job: submitted.append(job) or ("sucesso", 99, ""), start=False)
    app = create_app(config, CredentialStore(), auth=auth, connect=FakeConn, jobs=jobs)
    client = app.test_client()
    client.environ_base.update(LAN)
    return dict(client=client, repo=repo, auth=auth, jobs=jobs, submitted=submitted, audit=tmp_path / "auditoria.jsonl")


def login(env, email="ana@contego.com.br", oid=None):
    env["auth"].identity = Identity(email, email.split("@")[0], oid or f"oid-{email}")
    c = env["client"]
    assert c.get("/login", base_url="https://jervis.local").status_code == 302
    response = c.get("/auth/callback?code=abc&state=s1", base_url="https://jervis.local")
    if response.status_code == 302:
        return c.get("/api/me", base_url="https://jervis.local").get_json()["csrf"]
    return response


def call(env, method, path, csrf=None, **kwargs):
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    return env["client"].open(path, method=method, headers=headers, base_url="https://jervis.local", **kwargs)


# --- rede, login e sessão --------------------------------------------------------------------


def test_only_allowed_networks_reach_the_app(env):
    assert env["client"].get("/", base_url="https://jervis.local", environ_base={"REMOTE_ADDR": "8.8.8.8"}).status_code == 403
    assert call(env, "GET", "/").status_code == 302  # rede interna: vai para o login


def test_unauthenticated_requests(env):
    assert call(env, "GET", "/").headers["Location"].endswith("/login")
    assert call(env, "GET", "/api/reviews").status_code == 401


def test_login_redirects_to_microsoft_and_records_the_user(env):
    response = call(env, "GET", "/login")
    assert response.headers["Location"].startswith("https://login.microsoftonline.com/")
    csrf = login(env)
    me = call(env, "GET", "/api/me").get_json()
    assert me["perfil"] == "revisor" and me["csrf"] == csrf
    assert env["repo"].logins == [(1, "oid-ana@contego.com.br", "ana")]
    event = json.loads(env["audit"].read_text(encoding="utf-8").splitlines()[-1])
    assert event["evento"] == "web_login" and event["usuario"] == "ana@contego.com.br" and event["acesso"] == "web"


def test_microsoft_account_without_access_is_refused(env):
    response = login(env, "estranho@contego.com.br")
    assert response.status_code == 403
    assert "jervis web users add estranho@contego.com.br" in response.get_data(as_text=True)
    assert call(env, "GET", "/api/reviews").status_code == 401


def test_reused_email_with_another_account_id_is_refused(env):
    env["repo"].users[1].entra_oid = "oid-original"
    assert login(env, oid="oid-outra-pessoa").status_code == 403


def test_failed_microsoft_login_shows_reason(env):
    env["auth"].error = "Essa conta é de outra organização."
    response = login(env)
    assert response.status_code == 401 and "outra organização" in response.get_data(as_text=True)


def test_callback_without_started_login_restarts(env):
    assert call(env, "GET", "/auth/callback?code=x&state=s1").headers["Location"].endswith("/login")


def test_suspended_access_ends_the_session_immediately(env):
    login(env)
    env["repo"].users[1].active = False
    assert call(env, "GET", "/api/reviews").status_code == 401


def test_logout(env):
    csrf = login(env)
    assert call(env, "POST", "/logout", csrf).headers["Location"].endswith("/saiu")
    assert call(env, "GET", "/api/me").status_code == 401


def test_security_headers(env):
    headers = call(env, "GET", "/login").headers
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"] and headers["X-Content-Type-Options"] == "nosniff"


# --- revisões -------------------------------------------------------------------------------


def test_review_list_hides_replaced_and_reads_platform_status(env):
    login(env)
    data = call(env, "GET", "/api/reviews?month=2026-09").get_json()
    assert [r["id"] for r in data["relatorios"]] == [10, 11, 12]
    alfa = data["relatorios"][0]
    assert [(p["plataforma"], p["status"]) for p in alfa["plataformas"]] == [("acronis", "sucesso"), ("sophos", "falha")]
    assert alfa["plataformas"][0]["contagens"] == {"maquinas": 7}
    assert call(env, "GET", "/api/reviews?month=09-2026").status_code == 400


def test_review_detail_lists_errors_and_files(env):
    login(env)
    data = call(env, "GET", "/api/reviews/10").get_json()
    assert data["plataformas"][1]["erros"] == ["Há 2 tenants"]
    assert [f["nome"] for f in data["arquivos"]] == ["relatorio_executivo.pdf", "relatorio_mensal.xlsx"]


def test_actions_require_the_session_token(env):
    csrf = login(env)
    assert call(env, "POST", "/api/reviews/10/approve", json={}).status_code == 403
    assert call(env, "POST", "/api/reviews/10/approve", "token-errado", json={}).status_code == 403
    response = call(env, "POST", "/api/reviews/10/approve", csrf, json={"nota": " conferido "})
    assert response.status_code == 200
    assert env["repo"].reviews == [(10, "aprovado", "ana@contego.com.br", "conferido")]
    event = json.loads(env["audit"].read_text(encoding="utf-8").splitlines()[-1])
    assert event["evento"] == "relatorio_aprovado" and event["usuario"] == "ana@contego.com.br" and event["ip"] == "192.168.0.10"


def test_read_only_profile_cannot_approve(env):
    csrf = login(env, "bruno@contego.com.br")
    response = call(env, "POST", "/api/reviews/10/approve", csrf, json={})
    assert response.status_code == 403 and "leitura" in response.get_json()["erro"]
    assert env["repo"].reviews == []


def test_reject_requires_reason(env):
    csrf = login(env)
    assert call(env, "POST", "/api/reviews/10/reject", csrf, json={"motivo": "  "}).status_code == 400
    assert call(env, "POST", "/api/reviews/10/reject", csrf, json={"motivo": "faltou o Zabbix"}).status_code == 200
    assert env["repo"].reviews[-1] == (10, "rejeitado", "ana@contego.com.br", "faltou o Zabbix")


def test_bulk_approve_skips_reports_no_longer_pending(env):
    csrf = login(env)
    response = call(env, "POST", "/api/reviews/approve", csrf, json={"ids": [10, 11, 12]}).get_json()
    assert response["aprovados"] == [10, 12] and "Beta" in response["mensagem"]
    assert call(env, "POST", "/api/reviews/approve", csrf, json={"ids": "todos"}).status_code == 400


def test_approving_twice_explains(env):
    csrf = login(env)
    call(env, "POST", "/api/reviews/10/approve", csrf, json={})
    response = call(env, "POST", "/api/reviews/10/approve", csrf, json={})
    assert response.status_code == 400 and "não está pendente" in response.get_json()["erro"]


def test_regenerate_and_reopen_are_admin_only(env):
    csrf = login(env)
    assert call(env, "POST", "/api/reviews/11/regenerate", csrf).status_code == 403
    assert call(env, "POST", "/api/reviews/10/reopen", csrf).status_code == 403
    csrf = login(env, "carla@contego.com.br")
    assert call(env, "POST", "/api/reviews/11/regenerate", csrf).get_json()["ok"]
    call(env, "POST", "/api/reviews/11/regenerate", csrf)  # pedido repetido: não duplica
    assert [j["customer"] for j in env["jobs"].list()] == ["Beta"]
    env["jobs"].run_next()
    job = env["jobs"].list()[0]
    assert job["status"] == DONE and job["report_id"] == 99 and job["requested_by"] == "carla@contego.com.br"
    assert call(env, "POST", "/api/reviews/10/reopen", csrf).status_code == 200 and env["repo"].reopened == [10]


# --- arquivos ---------------------------------------------------------------------------------


def test_files_are_served_from_the_allowed_list_only(env):
    login(env)
    pdf = call(env, "GET", "/files/10/relatorio_executivo.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF") and "inline" in pdf.headers["Content-Disposition"]
    xlsx = call(env, "GET", "/files/10/relatorio_mensal.xlsx")
    assert "attachment" in xlsx.headers["Content-Disposition"] and "alfa_2026-09_relatorio_mensal.xlsx" in xlsx.headers["Content-Disposition"]
    assert call(env, "GET", "/files/10/consolidado.json").status_code == 404  # fora da lista
    assert call(env, "GET", "/files/10/..%2F..%2Fsecret.pdf").status_code == 404
    assert call(env, "GET", "/files/12/relatorio_executivo.pdf").status_code == 404  # pasta fora da saída
    assert call(env, "GET", "/files/10/relatorio_mensal.pdf").status_code == 404  # não gerado


# --- peças --------------------------------------------------------------------------------------


def test_jobs_report_failures_and_keep_running():
    calls = []

    def worker(job):
        calls.append(job.customer)
        if job.customer == "A":
            raise RuntimeError("quebrou")
        return "falha", 7, "[sophos] sem dados"

    jobs = Jobs(worker, start=False)
    jobs.submit(1, "A", "2026-09", "x@y.com")
    jobs.submit(2, "B", "2026-09", "x@y.com")
    jobs.run_next()
    jobs.run_next()
    first, second = sorted(jobs.list(), key=lambda j: j["id"])
    assert first["status"] == FAILED and "RuntimeError" in first["message"]
    assert second["status"] == FAILED and second["message"] == "[sophos] sem dados"


def test_entra_auth_checks_the_organization():
    class FakeMsal:
        def __init__(self, client_id, client_credential, authority):
            assert authority.endswith(TENANT) and client_credential == "segredo"

        def acquire_token_by_auth_code_flow(self, flow, params):
            return {"id_token_claims": {"tid": "outra-org", "preferred_username": "x@outra.com", "oid": "1"}}

    auth = EntraAuth(TENANT, CLIENT, lambda: "segredo", "https://jervis.local/auth/callback", app_factory=FakeMsal)
    with pytest.raises(AuthError, match="outra organização"):
        auth.finish({}, {})
    with pytest.raises(AuthError, match="set-secret"):
        EntraAuth(TENANT, CLIENT, lambda: None, "https://x/auth/callback").begin()


def test_web_config_validation():
    base = {"settings": {}, "platforms": {}}
    web = parse_config({**base, "web": {"public_url": "https://PC-TI:8443/", "tenant_id": TENANT.upper(), "client_id": CLIENT}}).web
    assert web.public_url == "https://PC-TI:8443" and web.redirect_uri == "https://PC-TI:8443/auth/callback"
    assert web.tenant_id == TENANT and web.missing() == []
    for bad in ({"public_url": "http://pc-ti:8443"}, {"tenant_id": "contego"}, {"allowed_networks": ["rede-interna"]},
                {"session_hours": 72}, {"porta": 1}):
        with pytest.raises(ConfigError):
            parse_config({**base, "web": bad})


def test_certificate_from_internal_authority(tmp_path):
    cert, key = tmp_path / "web" / "jervis-web.pem", tmp_path / "web" / "jervis-web.key"
    ca_file, created = certs.make_server_certificate(cert, key, ["pc-ti", "localhost"], ["127.0.0.1", "192.168.0.5"])
    assert created and ca_file.is_file() and key.is_file()
    expires, names = certs.certificate_info(cert)
    assert names == ["pc-ti", "localhost", "127.0.0.1", "192.168.0.5"]
    _, created_again = certs.make_server_certificate(cert, key, ["pc-ti"], ["127.0.0.1"])
    assert not created_again  # renovação reaproveita a autoridade já instalada na equipe

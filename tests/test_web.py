"""Interface web: rede permitida, contas próprias (senha, troca obrigatória, app autenticador, bloqueio), perfis,
proteção contra requisições forjadas, administração de contas e arquivos."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

from jervis.config import AppConfig, DatabaseConfig, Settings, WebConfig, parse_config
from jervis.credentials import CredentialStore
from jervis.db import crypto, repository
from jervis.db.repository import CustomerReport, RecordError, WebUser
from jervis.errors import ConfigError
from jervis.web import certs, create_app, passwords
from jervis.web.app import Throttle
from jervis.web.jobs import DONE, FAILED, Jobs

LAN = {"REMOTE_ADDR": "192.168.0.10"}
BASE = "https://jervis.local"
PASSWORD = "uma frase bem comprida"


class FakeConn:
    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def account(uid, email, role, password=PASSWORD, temporary=False, mfa=None, key=None):
    return WebUser(uid, email, email.split("@")[0].title(), role, True, passwords.hash_password(password), temporary,
                   crypto.encrypt_secret(mfa, key) if mfa else None, None, 0, None, 0, None)


class FakeRepo:
    """Banco em memória com as funções do repositório que a interface usa."""

    def __init__(self, output: Path, key: str):
        self.secret = pyotp.random_base32()
        self.users = {1: account(1, "ana@contego.com.br", "revisor", mfa=self.secret, key=key),
                      2: account(2, "bruno@contego.com.br", "leitura", mfa=self.secret, key=key),
                      3: account(3, "carla@contego.com.br", "admin", mfa=self.secret, key=key),
                      4: account(4, "novo@contego.com.br", "revisor", password="kq7m-x2pr-9fhw-t4za", temporary=True)}
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
        self.reviews, self.reopened = [], []

    def install(self, monkeypatch):
        r = repository
        monkeypatch.setattr(r, "get_web_user", lambda conn, uid: self.users.get(uid))
        monkeypatch.setattr(r, "find_web_user", lambda conn, email: next((u for u in self.users.values() if u.email == email), None))
        monkeypatch.setattr(r, "require_web_user", lambda conn, ref: self.users[ref] if isinstance(ref, int) else r.find_web_user(conn, ref))
        monkeypatch.setattr(r, "list_web_users", lambda conn: list(self.users.values()))
        monkeypatch.setattr(r, "add_web_user", self.add_web_user)
        monkeypatch.setattr(r, "update_web_user", self.update_web_user)
        monkeypatch.setattr(r, "set_web_password", self.set_web_password)
        monkeypatch.setattr(r, "set_web_mfa", self.set_web_mfa)
        monkeypatch.setattr(r, "use_mfa_step", lambda conn, uid, step: setattr(self.users[uid], "mfa_last_step", step))
        monkeypatch.setattr(r, "record_web_failure", self.record_web_failure)
        monkeypatch.setattr(r, "record_web_login", lambda conn, uid: setattr(self.users[uid], "failed_attempts", 0))
        monkeypatch.setattr(r, "list_reports", lambda conn, status, month: list(self.reports.values()))
        monkeypatch.setattr(r, "list_competencias", lambda conn: ["2026-09"])
        monkeypatch.setattr(r, "find_report", self.find_report)
        monkeypatch.setattr(r, "review_report", self.review_report)
        monkeypatch.setattr(r, "reopen_report", lambda conn, rid: self.reopened.append(rid))

    def add_web_user(self, conn, email, name, role, password_hash):
        if any(u.email == email for u in self.users.values()):
            raise RecordError(f"Já existe uma conta para {email}.")
        uid = max(self.users) + 1
        self.users[uid] = WebUser(uid, email, name, role, True, password_hash, True, None, None, 0, None, 0, None)
        return uid

    def update_web_user(self, conn, ref, role=None, active=None, name=None):
        u = self.users[ref]
        if active is False or (role and role != u.role):
            u.session_epoch += 1
        u.role, u.active = role or u.role, u.active if active is None else active
        return u

    def set_web_password(self, conn, uid, password_hash, temporary):
        u = self.users[uid]
        u.password_hash, u.must_change_password, u.failed_attempts, u.locked_until = password_hash, temporary, 0, None
        u.session_epoch += 1

    def set_web_mfa(self, conn, uid, secret_encrypted, last_step=None):
        u = self.users[uid]
        u.mfa_secret_encrypted, u.mfa_last_step = secret_encrypted, last_step
        if not secret_encrypted:
            u.session_epoch += 1

    def record_web_failure(self, conn, uid):
        u = self.users[uid]
        u.failed_attempts += 1
        if u.failed_attempts >= repository.LOCK_AFTER:
            u.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=15)
        return u.failed_attempts == repository.LOCK_AFTER

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
    store = CredentialStore()
    key = crypto.new_key()
    store.set_secret(crypto.VAULT_KEY, key)
    config = AppConfig(settings=Settings(output_dir=str(output), audit_file=str(tmp_path / "auditoria.jsonl")), platforms={},
                       web=WebConfig(public_url="https://jervis.local:8443"), database=DatabaseConfig())
    repo = FakeRepo(output, key)
    repo.install(monkeypatch)
    jobs = Jobs(lambda job: ("sucesso", 99, ""), start=False)
    app = create_app(config, store, connect=FakeConn, jobs=jobs, throttle=Throttle(limit=8))
    client = app.test_client()
    client.environ_base.update(LAN)
    return dict(client=client, repo=repo, jobs=jobs, audit=tmp_path / "auditoria.jsonl", app=app)


def get(env, path, **kw):
    return env["client"].get(path, base_url=BASE, **kw)


def form_csrf(env, path="/login"):
    html = get(env, path).get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def post_form(env, path, data, csrf=None):
    return env["client"].post(path, data={"csrf": csrf if csrf is not None else form_csrf(env, path), **data}, base_url=BASE)


def code(env, offset=0):
    return pyotp.TOTP(env["repo"].secret).at(datetime.now().timestamp() + offset)


def full_login(env, email="ana@contego.com.br", offset=0):
    """Senha + código do app; devolve o token da sessão para as ações."""
    assert post_form(env, "/login", {"email": email, "password": PASSWORD}).headers["Location"] == "/login/codigo"
    assert post_form(env, "/login/codigo", {"code": code(env, offset)}).headers["Location"] == "/"
    return get(env, "/api/me").get_json()["csrf"]


def call(env, method, path, csrf=None, **kwargs):
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    return env["client"].open(path, method=method, headers=headers, base_url=BASE, **kwargs)


def last_event(env):
    return json.loads(env["audit"].read_text(encoding="utf-8").splitlines()[-1])


# --- rede e páginas sem login -----------------------------------------------------------------


def test_only_allowed_networks_reach_the_app(env):
    assert get(env, "/login", environ_base={"REMOTE_ADDR": "8.8.8.8"}).status_code == 403
    assert get(env, "/").headers["Location"].endswith("/login")
    assert get(env, "/api/reviews").status_code == 401


def test_login_form_requires_its_token(env):
    assert post_form(env, "/login", {"email": "ana@contego.com.br", "password": PASSWORD}, csrf="").status_code == 403


def test_security_headers(env):
    headers = get(env, "/login").headers
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"] and headers["Cache-Control"] == "no-store"


# --- login ----------------------------------------------------------------------------------------


def test_login_with_password_and_app_code(env):
    csrf = full_login(env)
    me = get(env, "/api/me").get_json()
    assert me["perfil"] == "revisor" and me["csrf"] == csrf and me["mfa"]
    assert last_event(env)["evento"] == "web_login" and last_event(env)["usuario"] == "ana@contego.com.br"


def test_wrong_password_and_unknown_account_get_the_same_answer(env):
    wrong = post_form(env, "/login", {"email": "ana@contego.com.br", "password": "errada errada"})
    unknown = post_form(env, "/login", {"email": "ninguem@contego.com.br", "password": "errada errada"})
    assert wrong.status_code == unknown.status_code == 401
    assert "E-mail ou senha incorretos." in wrong.get_data(as_text=True) and "E-mail ou senha incorretos." in unknown.get_data(as_text=True)
    assert env["repo"].users[1].failed_attempts == 1


def test_account_locks_after_repeated_failures(env):
    for _ in range(repository.LOCK_AFTER):
        post_form(env, "/login", {"email": "ana@contego.com.br", "password": "errada errada"})
    response = post_form(env, "/login", {"email": "ana@contego.com.br", "password": PASSWORD})
    assert response.status_code == 423 and "bloqueada" in response.get_data(as_text=True)
    assert last_event(env)["evento"] == "web_conta_bloqueada"


def test_ip_limit_counts_failures_across_accounts(env):
    for i in range(8):
        post_form(env, "/login", {"email": f"x{i}@contego.com.br", "password": "errada errada"})
    assert post_form(env, "/login", {"email": "ana@contego.com.br", "password": PASSWORD}).status_code == 429


def test_wrong_and_reused_app_codes_are_refused(env):
    post_form(env, "/login", {"email": "ana@contego.com.br", "password": PASSWORD})
    assert post_form(env, "/login/codigo", {"code": "000000" if code(env) != "000000" else "111111"}).status_code == 401
    assert get(env, "/api/me").status_code == 401  # a etapa pendente não dá acesso
    full_code = code(env)
    assert post_form(env, "/login/codigo", {"code": full_code}).headers["Location"] == "/"
    call(env, "POST", "/logout", get(env, "/api/me").get_json()["csrf"])
    post_form(env, "/login", {"email": "ana@contego.com.br", "password": PASSWORD})
    assert post_form(env, "/login/codigo", {"code": full_code}).status_code == 401  # o mesmo código não vale duas vezes


def test_first_login_changes_temporary_password_then_sets_up_the_app(env):
    response = post_form(env, "/login", {"email": "novo@contego.com.br", "password": "kq7m-x2pr-9fhw-t4za"})
    assert response.headers["Location"] == "/conta/senha"
    assert get(env, "/").headers["Location"].endswith("/login")  # sem acesso até concluir
    weak = post_form(env, "/conta/senha", {"new": "curta", "confirm": "curta"})
    assert weak.status_code == 400 and "12 caracteres" in weak.get_data(as_text=True)
    different = post_form(env, "/conta/senha", {"new": "minha frase nova longa", "confirm": "outra frase nova longa"})
    assert "não são iguais" in different.get_data(as_text=True)
    assert post_form(env, "/conta/senha", {"new": "minha frase nova longa", "confirm": "minha frase nova longa"}).headers["Location"] == "/conta/mfa"
    page = get(env, "/conta/mfa").get_data(as_text=True)
    assert 'src="data:image/svg+xml' in page
    with env["client"].session_transaction(base_url=BASE) as s:
        secret = s["mfa_new"]
    assert post_form(env, "/conta/mfa", {"code": pyotp.TOTP(secret).now()}).headers["Location"] == "/"
    user = env["repo"].users[4]
    assert not user.must_change_password and user.mfa_configured and passwords.verify_password("minha frase nova longa", user.password_hash)
    assert get(env, "/api/me").get_json()["email"] == "novo@contego.com.br"


def test_changing_password_ends_other_sessions(env):
    csrf = full_login(env)
    other = env["app"].test_client()
    other.environ_base.update(LAN)
    with env["client"].session_transaction(base_url=BASE) as s:
        session_copy = dict(s)
    with other.session_transaction(base_url=BASE) as s:
        s.update(session_copy)
    assert other.get("/api/me", base_url=BASE).status_code == 200
    response = env["client"].post("/conta/senha", base_url=BASE, data={"csrf": csrf, "current": PASSWORD,
                                                                      "new": "outra frase bem comprida", "confirm": "outra frase bem comprida"})
    assert response.headers["Location"] == "/"
    assert get(env, "/api/me").status_code == 200  # esta continua
    assert other.get("/api/me", base_url=BASE).status_code == 401  # a outra cai


def test_logout(env):
    csrf = full_login(env)
    assert call(env, "POST", "/logout", csrf).headers["Location"].endswith("/saiu")
    assert get(env, "/api/me").status_code == 401


def test_suspended_account_leaves_immediately(env):
    full_login(env)
    env["repo"].users[1].active = False
    assert get(env, "/api/reviews").status_code == 401


# --- contas (admin) -------------------------------------------------------------------------------


def test_only_admins_manage_accounts(env):
    csrf = full_login(env)
    assert get(env, "/usuarios").status_code == 403
    assert call(env, "POST", "/api/users", csrf, json={"nome": "X", "email": "x@contego.com.br", "perfil": "leitura"}).status_code == 403


def test_admin_creates_account_and_resets_password(env):
    csrf = full_login(env, "carla@contego.com.br")
    assert get(env, "/usuarios").status_code == 200
    created = call(env, "POST", "/api/users", csrf, json={"nome": "Diego", "email": "Diego@Contego.com.br ", "perfil": "revisor"}).get_json()
    temporary = created["senha_temporaria"]
    assert re.fullmatch(r"[a-z2-9]{4}(-[a-z2-9]{4}){3}", temporary) and created["usuario"]["senha_temporaria"]
    assert temporary not in env["audit"].read_text(encoding="utf-8")  # senha nunca vai para a auditoria
    reset = call(env, "POST", "/api/users/1/reset-password", csrf).get_json()
    assert reset["senha_temporaria"] != temporary and env["repo"].users[1].must_change_password
    assert call(env, "POST", "/api/users/1/reset-mfa", csrf).get_json()["ok"] and not env["repo"].users[1].mfa_configured
    users = call(env, "GET", "/api/users").get_json()["usuarios"]
    assert any(u["voce"] and u["email"] == "carla@contego.com.br" for u in users)


def test_admin_cannot_lock_themselves_out(env):
    csrf = full_login(env, "carla@contego.com.br")
    assert call(env, "POST", "/api/users/3", csrf, json={"ativo": False}).status_code == 400
    assert call(env, "POST", "/api/users/3", csrf, json={"perfil": "leitura"}).status_code == 400
    assert call(env, "POST", "/api/users/3/reset-password", csrf).status_code == 400
    assert call(env, "POST", "/api/users/2", csrf, json={"perfil": "revisor"}).get_json()["usuario"]["perfil"] == "revisor"


def test_new_name_is_required(env):
    csrf = full_login(env, "carla@contego.com.br")
    assert call(env, "POST", "/api/users", csrf, json={"nome": " ", "email": "a@b.com", "perfil": "leitura"}).status_code == 400


# --- revisões -------------------------------------------------------------------------------------


def test_review_list_hides_replaced_and_reads_platform_status(env):
    full_login(env)
    data = get(env, "/api/reviews?month=2026-09").get_json()
    assert [r["id"] for r in data["relatorios"]] == [10, 11, 12]
    alfa = data["relatorios"][0]
    assert [(p["plataforma"], p["status"]) for p in alfa["plataformas"]] == [("acronis", "sucesso"), ("sophos", "falha")]
    assert alfa["plataformas"][0]["contagens"] == {"maquinas": 7}
    assert get(env, "/api/reviews?month=09-2026").status_code == 400


def test_review_detail_lists_errors_and_files(env):
    full_login(env)
    data = get(env, "/api/reviews/10").get_json()
    assert data["plataformas"][1]["erros"] == ["Há 2 tenants"]
    assert [f["nome"] for f in data["arquivos"]] == ["relatorio_executivo.pdf", "relatorio_mensal.xlsx"]


def test_actions_require_the_session_token(env):
    csrf = full_login(env)
    assert call(env, "POST", "/api/reviews/10/approve", json={}).status_code == 403
    assert call(env, "POST", "/api/reviews/10/approve", "token-errado", json={}).status_code == 403
    assert call(env, "POST", "/api/reviews/10/approve", csrf, json={"nota": " conferido "}).status_code == 200
    assert env["repo"].reviews == [(10, "aprovado", "ana@contego.com.br", "conferido")]
    event = last_event(env)
    assert event["evento"] == "relatorio_aprovado" and event["usuario"] == "ana@contego.com.br" and event["ip"] == "192.168.0.10"


def test_read_only_profile_cannot_approve(env):
    csrf = full_login(env, "bruno@contego.com.br")
    response = call(env, "POST", "/api/reviews/10/approve", csrf, json={})
    assert response.status_code == 403 and "leitura" in response.get_json()["erro"]


def test_reject_requires_reason(env):
    csrf = full_login(env)
    assert call(env, "POST", "/api/reviews/10/reject", csrf, json={"motivo": "  "}).status_code == 400
    assert call(env, "POST", "/api/reviews/10/reject", csrf, json={"motivo": "faltou o Zabbix"}).status_code == 200


def test_bulk_approve_skips_reports_no_longer_pending(env):
    csrf = full_login(env)
    response = call(env, "POST", "/api/reviews/approve", csrf, json={"ids": [10, 11, 12]}).get_json()
    assert response["aprovados"] == [10, 12] and "Beta" in response["mensagem"]
    assert call(env, "POST", "/api/reviews/approve", csrf, json={"ids": "todos"}).status_code == 400


def test_regenerate_and_reopen_are_admin_only(env):
    csrf = full_login(env)
    assert call(env, "POST", "/api/reviews/11/regenerate", csrf).status_code == 403
    call(env, "POST", "/logout", csrf)
    csrf = full_login(env, "carla@contego.com.br", offset=30)
    assert call(env, "POST", "/api/reviews/11/regenerate", csrf).get_json()["ok"]
    call(env, "POST", "/api/reviews/11/regenerate", csrf)  # pedido repetido: não duplica
    assert [j["customer"] for j in env["jobs"].list()] == ["Beta"]
    env["jobs"].run_next()
    job = env["jobs"].list()[0]
    assert job["status"] == DONE and job["report_id"] == 99 and job["requested_by"] == "carla@contego.com.br"
    assert call(env, "POST", "/api/reviews/10/reopen", csrf).status_code == 200 and env["repo"].reopened == [10]


def test_files_are_served_from_the_allowed_list_only(env):
    full_login(env)
    pdf = get(env, "/files/10/relatorio_executivo.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF") and "inline" in pdf.headers["Content-Disposition"]
    xlsx = get(env, "/files/10/relatorio_mensal.xlsx")
    assert "attachment" in xlsx.headers["Content-Disposition"]
    assert get(env, "/files/10/consolidado.json").status_code == 404
    assert get(env, "/files/10/..%2F..%2Fsecret.pdf").status_code == 404
    assert get(env, "/files/12/relatorio_executivo.pdf").status_code == 404  # pasta fora da saída
    assert get(env, "/files/10/relatorio_mensal.pdf").status_code == 404  # não gerado


# --- peças ------------------------------------------------------------------------------------------


def test_passwords_and_codes():
    stored = passwords.hash_password("uma frase bem comprida")
    assert stored.startswith("scrypt$") and passwords.verify_password("uma frase bem comprida", stored)
    assert not passwords.verify_password("outra", stored) and not passwords.verify_password("x", "lixo")
    assert passwords.password_problem("curta", "ana@x.com")
    assert passwords.password_problem("ana.souza e o jervis", "ana.souza@x.com")
    assert passwords.password_problem("aaaaaaaaaaaaaa", "b@x.com")
    assert passwords.password_problem("uma frase bem comprida", "ana@x.com") is None
    secret = pyotp.random_base32()
    now = 1_800_000_000
    step = passwords.verify_code(secret, pyotp.TOTP(secret).at(now), None, now=now)
    assert step == now // 30
    assert passwords.verify_code(secret, pyotp.TOTP(secret).at(now), step, now=now) is None  # reutilizado
    assert passwords.verify_code(secret, pyotp.TOTP(secret).at(now - 300), None, now=now) is None  # velho


def test_jobs_report_failures_and_keep_running():
    def worker(job):
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


def test_web_config_validation():
    base = {"settings": {}, "platforms": {}}
    web = parse_config({**base, "web": {"public_url": "https://PC-TI:8443/", "mfa": "admin"}}).web
    assert web.public_url == "https://PC-TI:8443" and web.mfa_required("admin") and not web.mfa_required("revisor")
    assert WebConfig().mfa_required("leitura")  # padrão: todos
    for bad in ({"public_url": "http://pc-ti:8443"}, {"mfa": "as vezes"}, {"allowed_networks": ["rede-interna"]},
                {"session_hours": 72}, {"tenant_id": "x"}):
        with pytest.raises(ConfigError):
            parse_config({**base, "web": bad})


def test_certificate_from_internal_authority(tmp_path):
    cert, key = tmp_path / "web" / "jervis-web.pem", tmp_path / "web" / "jervis-web.key"
    ca_file, created = certs.make_server_certificate(cert, key, ["pc-ti", "localhost"], ["127.0.0.1", "192.168.0.5"])
    assert created and ca_file.is_file() and key.is_file()
    expires, names = certs.certificate_info(cert)
    assert names == ["pc-ti", "localhost", "127.0.0.1", "192.168.0.5"]
    _, created_again = certs.make_server_certificate(cert, key, ["pc-ti"], ["127.0.0.1"])
    assert not created_again

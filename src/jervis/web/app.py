"""Interface web da equipe: revisão dos relatórios mensais.

Contas próprias do Jervis: o admin cria os logins dos colegas (senha temporária, trocada no primeiro acesso) e cada
um configura o app autenticador (web.mfa). Perfis:
- leitura: vê os relatórios e abre os arquivos;
- revisor: também aprova e rejeita;
- admin: também gera de novo, desfaz revisões e administra as contas.

Proteções: só aceita conexões das redes configuradas (rede interna/VPN), sempre por HTTPS (server.py); senhas com
scrypt; bloqueio da conta após tentativas erradas e limite por IP; sessão em cookie assinado (Secure, HttpOnly,
SameSite) que cai ao trocar a senha ou suspender a conta; toda ação exige o token da sessão (contra requisições
forjadas por outros sites); o perfil é relido do banco a cada requisição; arquivos só da pasta de saída e de uma
lista fixa; cada ação fica na trilha de auditoria com o e-mail da pessoa e o IP.
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, send_file, session

from jervis import db, scheduling
from jervis.audit import AuditLog
from jervis.db import crypto, repository
from jervis.errors import JervisError
from jervis.security import redact
from jervis.web import passwords
from jervis.web.jobs import Job, Jobs

log = logging.getLogger(__name__)

SESSION_SECRET = "web:session_key"
ROLE_LEVEL = {"leitura": 1, "revisor": 2, "admin": 3}
# Arquivos que a interface entrega (nada fora desta lista, nem fora da pasta de saída)
FILES = {
    "relatorio_executivo.pdf": ("Relatório executivo", "Visão para a diretoria", True),
    "relatorio_mensal.pdf": ("Relatório mensal", "Relatório detalhado do mês", True),
    "relatorio_mensal.xlsx": ("Planilha", "Registros do mês, para filtrar", False),
    "resumo.md": ("Resumo", "Texto de apoio para a equipe", False),
}
_STATUS_IN_HEAD = re.compile(r'"status":\s*"(\w+)"')
_COUNTS_IN_HEAD = re.compile(r'"counts":\s*(\{[^{}]*\})')

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
IP_FAILURES, IP_WINDOW = 20, 15 * 60  # tentativas erradas por IP em 15 minutos, somando todas as contas


class Throttle:
    """Limite de tentativas erradas por IP (memória do servidor)."""

    def __init__(self, limit: int = IP_FAILURES, window: int = IP_WINDOW, clock: Callable[[], float] = time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def blocked(self, ip: str) -> bool:
        with self._lock:
            hits = self._hits.get(ip)
            while hits and self.clock() - hits[0] > self.window:
                hits.popleft()
            return bool(hits) and len(hits) >= self.limit

    def fail(self, ip: str) -> None:
        with self._lock:
            self._hits.setdefault(ip, deque()).append(self.clock())


def session_key(store) -> str:
    """Chave que assina os cookies de sessão: criada na primeira vez e guardada no cofre."""
    key = store.get_secret(SESSION_SECRET)
    if not key:
        key = secrets.token_urlsafe(48)
        store.set_secret(SESSION_SECRET, key)
    return key


def create_app(config, store, connect: Callable[[], Any] | None = None, jobs: Jobs | None = None,
               run_customer: Callable | None = None, throttle: Throttle | None = None) -> Flask:
    web = config.web
    app = Flask(__name__, static_folder="static", static_url_path="/static", template_folder="templates")
    app.config.update(
        SECRET_KEY=session_key(store), SESSION_COOKIE_NAME="jervis_session", SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=web.session_hours), MAX_CONTENT_LENGTH=64 * 1024,
    )
    networks = [ipaddress.ip_network(n, strict=False) for n in web.allowed_networks]
    output_dir = Path(config.settings.output_dir).resolve()
    throttle = throttle or Throttle()
    connect = connect or (lambda: db.connect(config.database, store))
    trail = AuditLog(config.settings.audit_file, config.environment)

    @contextlib.contextmanager
    def database():
        conn = connect()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def audit(event: str, **details) -> None:
        user = g.get("user")
        by = {"usuario": user.email if user else "anônimo", "maquina": socket.gethostname(), "acesso": "web",
              "ip": request.remote_addr or "?"}
        try:
            trail.record(event, by=by, **details)
        except OSError as exc:  # a ação já foi feita; registra no log da aplicação
            log.error("Auditoria não registrada (%s): %s", event, exc)

    # --- geração em segundo plano ---------------------------------------------------------

    def regenerate(job: Job) -> tuple[str, int | None, str]:
        from jervis.api import closing, collect

        if run_customer is None:
            from jervis.api.run import run_customer as runner
        else:
            runner = run_customer
        period = collect.month(job.competencia)
        with database() as conn:
            customer = repository.find_customer(conn, str(job.customer_id))
            outcome = closing.run_customers(config, store, conn, [customer], period, runner, origin="web",
                                            user=job.requested_by, emit=lambda line: log.info("%s", line))[0]
        try:
            trail.record("relatorio_cliente", by={"usuario": job.requested_by, "maquina": socket.gethostname(),
                                                  "acesso": "web"},
                         cliente=customer.name, competencia=job.competencia, resultado=outcome.resultado,
                         revisao=outcome.report_id, execucao=str(outcome.run_dir) if outcome.run_dir else None)
        except OSError as exc:
            log.error("Auditoria não registrada (relatorio_cliente): %s", exc)
        return outcome.resultado, outcome.report_id, outcome.detalhe

    jobs = jobs or Jobs(regenerate)

    # --- proteções em toda requisição ------------------------------------------------------

    @app.before_request
    def guard():
        try:
            address = ipaddress.ip_address((request.remote_addr or "").split("%")[0])
        except ValueError:
            abort(403)
        if not any(address in net for net in networks):
            log.warning("Acesso recusado de %s (fora das redes permitidas)", address)
            abort(403)
        g.user = None
        if request.path.startswith("/static/"):
            return None
        user_id = session.get("user_id")
        if user_id:
            with database() as conn:
                user = repository.get_web_user(conn, user_id)
            # senha trocada, conta suspensa ou perfil mudado em outra sessão: esta sessão cai
            if user and user.active and user.session_epoch == session.get("epoch") and not user.must_change_password:
                g.user = user
            else:
                session.clear()
        if request.method not in ("GET", "HEAD"):
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf") or ""
            if not hmac.compare_digest(token, session.get("csrf", "")) or not token:
                abort(403)

    @app.after_request
    def headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def require(role: str):
        def decorator(view):
            @wraps(view)
            def wrapper(*args, **kwargs):
                if not g.user:
                    return jsonify(erro="Sessão expirada. Entre de novo."), 401
                if ROLE_LEVEL.get(g.user.role, 0) < ROLE_LEVEL[role]:
                    return jsonify(erro=f"Seu perfil ({g.user.role}) não permite essa ação."), 403
                return view(*args, **kwargs)
            return wrapper
        return decorator

    @app.errorhandler(JervisError)
    def jervis_error(exc):
        if request.path.startswith("/api/"):
            return jsonify(erro=redact(str(exc))), 400
        return page("message.html", "Não foi possível concluir", message=redact(str(exc)), link="/", link_label="Voltar"), 400

    @app.errorhandler(403)
    def forbidden(exc):
        if request.path.startswith("/api/"):
            return jsonify(erro="Acesso negado."), 403
        return page("message.html", "Acesso negado", message="Este endereço não está liberado para você, ou a página "
                    "expirou. Volte e tente de novo.", link="/login", link_label="Ir para o login"), 403

    def page(template: str, title: str, **context):
        session.setdefault("csrf", secrets.token_urlsafe(32))  # formulários antes do login também levam o token
        return render_template(template, title=title, csrf=session["csrf"], **context)

    def utcnow() -> datetime:
        return datetime.now(timezone.utc).replace(tzinfo=None)  # o banco guarda UTC sem fuso

    def mfa_key() -> str:
        return crypto.load_key(store)

    # --- login: senha, troca da senha temporária, app autenticador ------------------------
    # Entre as etapas, a sessão guarda só "pending" (id da conta e versão); o login completo vem no fim.

    def pending_user():
        pending = session.get("pending") or {}
        if not pending.get("uid"):
            return None
        with database() as conn:
            user = repository.get_web_user(conn, pending["uid"])
        if not user or not user.active or user.session_epoch != pending.get("epoch"):
            session.clear()
            return None
        return user

    def next_step(user):
        """Próxima etapa do login: troca da senha temporária, app autenticador ou entrada."""
        pending = session["pending"]
        if user.must_change_password:
            return redirect("/conta/senha")
        if web.mfa_required(user.role) and not pending.get("mfa_ok"):
            return redirect("/login/codigo" if user.mfa_configured else "/conta/mfa")
        return finish_login(user)

    def finish_login(user):
        session.clear()
        session.permanent = True
        session.update(user_id=user.id, epoch=user.session_epoch, csrf=secrets.token_urlsafe(32))
        with database() as conn:
            repository.record_web_login(conn, user.id)
        g.user = user
        audit("web_login")
        return redirect("/")

    def failed(user, what: str) -> bool:
        """Tentativa errada: conta para o IP e para a conta. Devolve True se a conta foi bloqueada agora."""
        throttle.fail(request.remote_addr or "?")
        if not user:
            return False
        with database() as conn:
            locked = repository.record_web_failure(conn, user.id)
        if locked:
            audit("web_conta_bloqueada", email=user.email, motivo=what)
        return locked

    @app.get("/login")
    def login():
        if g.user:
            return redirect("/")
        return page("login.html", "Entrar")

    @app.post("/login")
    def login_post():
        ip = request.remote_addr or "?"
        email = (request.form.get("email") or "").strip().lower()[:255]
        password = request.form.get("password") or ""
        if throttle.blocked(ip):
            return page("login.html", "Entrar", email=email,
                        error="Muitas tentativas erradas a partir deste computador. Espere 15 minutos."), 429
        with database() as conn:
            user = repository.find_web_user(conn, email)
        if user and user.locked_until and user.locked_until > utcnow():
            local = user.locked_until.replace(tzinfo=timezone.utc).astimezone()
            return page("login.html", "Entrar", email=email,
                        error=f"Conta bloqueada por tentativas erradas até {local:%H:%M}. Ou peça a um administrador "
                              "para redefinir a senha."), 423
        valid = passwords.verify_password(password, user.password_hash if user else passwords.DUMMY_HASH)
        if not valid or not user or not user.active:
            failed(user if user and user.active else None, "senha")
            log.warning("Login recusado para %s a partir de %s", email or "?", ip)
            return page("login.html", "Entrar", email=email, error="E-mail ou senha incorretos."), 401
        session.clear()
        session["pending"] = {"uid": user.id, "epoch": user.session_epoch}
        return next_step(user)

    @app.get("/login/codigo")
    def code_page():
        user = pending_user()
        if not user or not user.mfa_configured:
            return redirect("/login")
        return page("codigo.html", "Código do app autenticador")

    @app.post("/login/codigo")
    def code_post():
        user = pending_user()
        if not user or not user.mfa_configured:
            return redirect("/login")
        if throttle.blocked(request.remote_addr or "?") or (user.locked_until and user.locked_until > utcnow()):
            session.clear()
            return page("message.html", "Conta bloqueada", message="Muitas tentativas erradas. Espere 15 minutos "
                        "ou peça a um administrador.", link="/login", link_label="Voltar ao login"), 423
        secret = crypto.decrypt_secret(user.mfa_secret_encrypted, mfa_key()).reveal()
        step = passwords.verify_code(secret, request.form.get("code", ""), user.mfa_last_step)
        if step is None:
            if failed(user, "codigo"):
                session.clear()
                return page("message.html", "Conta bloqueada", message="Muitas tentativas erradas. Espere 15 minutos "
                            "ou peça a um administrador.", link="/login", link_label="Voltar ao login"), 423
            return page("codigo.html", "Código do app autenticador", error="Código incorreto ou expirado. Use o código atual do app."), 401
        with database() as conn:
            repository.use_mfa_step(conn, user.id, step)
        session["pending"] = {**session["pending"], "mfa_ok": True}
        session.modified = True
        return next_step(user)

    @app.route("/conta/mfa", methods=["GET", "POST"])
    def mfa_setup():
        """Configura o app autenticador: no primeiro login (etapa pendente) ou, logado, para trocar de celular."""
        user = g.user or pending_user()
        if not user:
            return redirect("/login")
        if not g.user and (user.must_change_password or user.mfa_configured):
            return redirect("/login")  # na etapa pendente, só quem ainda não configurou
        secret = session.get("mfa_new")
        if not secret:
            secret = session["mfa_new"] = passwords.new_mfa_secret()
        context = dict(qr=passwords.qr_svg(passwords.provisioning_uri(secret, user.email)),
                       secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))
        if request.method == "GET":
            return page("mfa.html", "Configure o app autenticador", **context)
        step = passwords.verify_code(secret, request.form.get("code", ""), None)
        if step is None:
            throttle.fail(request.remote_addr or "?")
            return page("mfa.html", "Configure o app autenticador", error="Código incorreto. Confira se leu o QR code "
                        "e digite o código atual do app.", **context), 400
        with database() as conn:
            repository.set_web_mfa(conn, user.id, crypto.encrypt_secret(secret, mfa_key()), step)
        session.pop("mfa_new", None)
        audit("web_mfa_configurado", email=user.email)
        if g.user:
            return page("message.html", "App autenticador configurado", message="Nos próximos logins, use o código "
                        "do app novo.", link="/", link_label="Voltar")
        session["pending"] = {**session["pending"], "mfa_ok": True}
        session.modified = True
        return next_step(user)

    @app.route("/conta/senha", methods=["GET", "POST"])
    def change_password():
        """Troca de senha: obrigatória após senha temporária (etapa pendente) ou, logado, quando quiser."""
        user = g.user or pending_user()
        if not user:
            return redirect("/login")
        forced = not g.user
        if forced and not user.must_change_password:
            return redirect("/login")
        context = dict(forced=forced, email=user.email)
        if request.method == "GET":
            return page("senha.html", "Crie a sua senha" if forced else "Trocar senha", **context)
        new, confirm = request.form.get("new") or "", request.form.get("confirm") or ""
        if not forced and not passwords.verify_password(request.form.get("current") or "", user.password_hash):
            failed(user, "senha_atual")
            return page("senha.html", "Trocar senha", error="Senha atual incorreta.", **context), 401
        problem = passwords.password_problem(new, user.email)
        if not problem and new != confirm:
            problem = "As duas senhas não são iguais."
        if not problem and passwords.verify_password(new, user.password_hash):
            problem = "A nova senha tem que ser diferente da atual."
        if problem:
            return page("senha.html", "Crie a sua senha" if forced else "Trocar senha", error=problem, **context), 400
        with database() as conn:
            repository.set_web_password(conn, user.id, passwords.hash_password(new), temporary=False)
            user = repository.get_web_user(conn, user.id)
        audit("web_senha_trocada", email=user.email)
        if forced:  # continua o login com a versão nova da conta
            session["pending"] = {**session["pending"], "epoch": user.session_epoch}
            session.modified = True
            return next_step(user)
        return finish_login(user)  # logado: as outras sessões caem, esta continua

    @app.post("/logout")
    def logout():
        audit("web_logout")
        session.clear()
        return redirect("/saiu")

    @app.get("/saiu")
    def logged_out():
        return page("message.html", "Você saiu do Jervis", message="Até a próxima.", link="/login", link_label="Entrar de novo")

    # --- página -------------------------------------------------------------------------

    @app.get("/")
    def index():
        if not g.user:
            return redirect("/login")
        return app.send_static_file("index.html")

    @app.get("/usuarios")
    def users_page():
        if not g.user:
            return redirect("/login")
        if g.user.role != "admin":
            abort(403)
        return app.send_static_file("usuarios.html")

    # --- API ------------------------------------------------------------------------------

    @app.get("/api/me")
    @require("leitura")
    def me():
        u = g.user
        return jsonify(email=u.email, nome=u.name or u.email, perfil=u.role, csrf=session["csrf"],
                       mfa=u.mfa_configured, mfa_obrigatorio=web.mfa_required(u.role))

    @app.get("/api/overview")
    @require("leitura")
    def overview():
        with database() as conn:
            months = repository.list_competencias(conn)
        now = datetime.now()
        closes = [s for s in config.schedules.values() if s.enabled and s.task == "relatorios_clientes"]
        upcoming = min((scheduling.next_run(s, now) for s in closes), default=None)
        return jsonify(competencias=months, proximo_fechamento=upcoming.strftime("%d/%m %H:%M") if upcoming else None)

    @app.get("/api/reviews")
    @require("leitura")
    def reviews():
        month = request.args.get("month") or None
        if month and not re.fullmatch(r"\d{4}-\d{2}", month):
            return jsonify(erro="Competência inválida (use AAAA-MM)."), 400
        with database() as conn:
            reports = [r for r in repository.list_reports(conn, None, month) if r.status != "substituido"]
            names = {u.email: u.name for u in repository.list_web_users(conn)}
        return jsonify(relatorios=[_summary(r, names) for r in reports], jobs=jobs.list())

    @app.get("/api/reviews/<int:report_id>")
    @require("leitura")
    def review_detail(report_id: int):
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            names = {u.email: u.name for u in repository.list_web_users(conn)}
        data = _summary(report, names)
        data["plataformas"] = _platforms(report, full=True)
        data["arquivos"] = [{"nome": name, "titulo": t, "descricao": d, "vai_ao_cliente": send}
                            for name, (t, d, send) in FILES.items() if _file(report, name)]
        return jsonify(data)

    @app.post("/api/reviews/<int:report_id>/approve")
    @require("revisor")
    def approve(report_id: int):
        note = _text("nota", 1024)
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            repository.review_report(conn, report.id, "aprovado", g.user.email, note)
        audit("relatorio_aprovado", revisao=report.id, cliente=report.customer, competencia=report.competencia,
              pasta=report.run_dir, observacao=note)
        return jsonify(ok=True, mensagem=f"{report.customer}: aprovado.")

    @app.post("/api/reviews/approve")
    @require("revisor")
    def approve_many():
        body = request.get_json(silent=True) or {}
        ids = body.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids) or len(ids) > 500:
            return jsonify(erro="Selecione os relatórios a aprovar."), 400
        approved, skipped = [], []
        with database() as conn:
            for report_id in ids:
                report = repository.find_report(conn, f"#{report_id}")
                if report.status != "pendente":
                    skipped.append(report.customer)
                    continue
                repository.review_report(conn, report.id, "aprovado", g.user.email, None)
                approved.append(report)
        for report in approved:
            audit("relatorio_aprovado", revisao=report.id, cliente=report.customer, competencia=report.competencia,
                  pasta=report.run_dir, em_lote=True)
        message = f"{len(approved)} relatório(s) aprovado(s)."
        if skipped:
            message += f" {len(skipped)} já não estavam pendentes: {', '.join(skipped)}."
        return jsonify(ok=True, mensagem=message, aprovados=[r.id for r in approved])

    @app.post("/api/reviews/<int:report_id>/reject")
    @require("revisor")
    def reject(report_id: int):
        reason = _text("motivo", 1024)
        if not reason:
            return jsonify(erro="Escreva o motivo da rejeição."), 400
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            repository.review_report(conn, report.id, "rejeitado", g.user.email, reason)
        audit("relatorio_rejeitado", revisao=report.id, cliente=report.customer, competencia=report.competencia,
              pasta=report.run_dir, observacao=reason)
        return jsonify(ok=True, mensagem=f"{report.customer}: rejeitado.")

    @app.post("/api/reviews/<int:report_id>/reopen")
    @require("admin")
    def reopen(report_id: int):
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
            repository.reopen_report(conn, report.id)
        audit("relatorio_reaberto", revisao=report.id, cliente=report.customer, competencia=report.competencia,
              situacao_anterior=report.status)
        return jsonify(ok=True, mensagem=f"{report.customer} voltou para pendente.")

    @app.post("/api/reviews/<int:report_id>/regenerate")
    @require("admin")
    def regenerate_report(report_id: int):
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
        if not report.competencia:
            return jsonify(erro="Só relatórios mensais podem ser gerados de novo pela interface."), 400
        job = jobs.submit(report.customer_id, report.customer, report.competencia, g.user.email)
        audit("relatorio_pedido", revisao=report.id, cliente=report.customer, competencia=report.competencia, fila=job.id)
        return jsonify(ok=True, mensagem=f"{report.customer}: geração na fila. Leva cerca de um minuto.", job=job.id)

    @app.get("/api/jobs")
    @require("leitura")
    def job_list():
        return jsonify(jobs=jobs.list())

    # --- contas (admin) ------------------------------------------------------------------

    def user_view(u) -> dict[str, Any]:
        locked = bool(u.locked_until and u.locked_until > utcnow())
        return {"id": u.id, "email": u.email, "nome": u.name, "perfil": u.role, "ativo": u.active,
                "mfa": u.mfa_configured, "senha_temporaria": u.must_change_password, "bloqueada": locked,
                "ultimo_login": _local(u.last_login_at), "voce": bool(g.user and u.id == g.user.id)}

    @app.get("/api/users")
    @require("admin")
    def users_list():
        with database() as conn:
            people = repository.list_web_users(conn)
        return jsonify(usuarios=[user_view(u) for u in people], mfa=web.mfa)

    @app.post("/api/users")
    @require("admin")
    def users_create():
        body = request.get_json(silent=True) or {}
        role = body.get("perfil")
        name = (body.get("nome") or "").strip()[:255]
        if not name:
            return jsonify(erro="Informe o nome da pessoa."), 400
        temporary = passwords.temporary_password()
        with database() as conn:
            user_id = repository.add_web_user(conn, body.get("email") or "", name, role, passwords.hash_password(temporary))
            user = repository.get_web_user(conn, user_id)
        audit("web_usuario_criado", email=user.email, perfil=user.role)
        return jsonify(ok=True, mensagem=f"Conta de {name} criada.", usuario=user_view(user), senha_temporaria=temporary)

    @app.post("/api/users/<int:user_id>")
    @require("admin")
    def users_update(user_id: int):
        body = request.get_json(silent=True) or {}
        role, active = body.get("perfil"), body.get("ativo")
        if active is not None and not isinstance(active, bool):
            return jsonify(erro="Situação inválida."), 400
        if user_id == g.user.id and (active is False or (role and role != "admin")):
            return jsonify(erro="Você não pode suspender nem rebaixar a sua própria conta."), 400
        with database() as conn:
            user = repository.update_web_user(conn, user_id, role=role, active=active)
        audit("web_usuario_alterado", email=user.email, perfil=user.role, ativo=user.active)
        return jsonify(ok=True, mensagem=f"{user.name or user.email}: alterado.", usuario=user_view(user))

    @app.post("/api/users/<int:user_id>/reset-password")
    @require("admin")
    def users_reset_password(user_id: int):
        if user_id == g.user.id:
            return jsonify(erro="Para a sua conta, use Trocar senha."), 400
        temporary = passwords.temporary_password()
        with database() as conn:
            user = repository.require_web_user(conn, user_id)
            repository.set_web_password(conn, user.id, passwords.hash_password(temporary), temporary=True)
            user = repository.get_web_user(conn, user.id)
        audit("web_senha_redefinida", email=user.email)
        return jsonify(ok=True, mensagem=f"Senha de {user.name or user.email} redefinida.", usuario=user_view(user),
                       senha_temporaria=temporary)

    @app.post("/api/users/<int:user_id>/reset-mfa")
    @require("admin")
    def users_reset_mfa(user_id: int):
        with database() as conn:
            user = repository.require_web_user(conn, user_id)
            repository.set_web_mfa(conn, user.id, None)
            user = repository.get_web_user(conn, user.id)
        audit("web_mfa_redefinido", email=user.email)
        return jsonify(ok=True, mensagem=f"{user.name or user.email} vai configurar o app autenticador no próximo login.",
                       usuario=user_view(user))

    @app.get("/files/<int:report_id>/<name>")
    @require("leitura")
    def file(report_id: int, name: str):
        if name not in FILES:
            abort(404)
        with database() as conn:
            report = repository.find_report(conn, f"#{report_id}")
        path = _file(report, name)
        if not path:
            abort(404)
        audit("relatorio_aberto", revisao=report.id, cliente=report.customer, arquivo=name)
        pdf = name.endswith(".pdf")
        download = f"{_slug(report.customer)}_{report.competencia or 'periodo'}_{name}"
        return send_file(path, as_attachment=not pdf, download_name=download,
                         mimetype="text/markdown; charset=utf-8" if name.endswith(".md") else None)

    # --- auxiliares ---------------------------------------------------------------------

    def _file(report, name: str) -> Path | None:
        if not report.run_dir:
            return None
        folder = Path(report.run_dir).resolve()
        if not folder.is_relative_to(output_dir):  # pasta registrada fora da saída: nunca entrega
            log.warning("Pasta fora da saída recusada: %s", folder)
            return None
        path = folder / name
        return path if path.is_file() else None

    def _summary(report, names: dict[str, str | None]) -> dict[str, Any]:
        return {
            "id": report.id, "cliente": report.customer, "cliente_id": report.customer_id,
            "competencia": report.competencia, "periodo": report.periodo, "resultado": report.resultado,
            "situacao": report.status, "origem": report.origem, "gerado_por": report.gerado_por,
            "gerado_em": _local(report.gerado_em), "revisado_por": names.get(report.revisado_por) or report.revisado_por,
            "revisado_em": _local(report.revisado_em), "observacao": report.observacao,
            "plataformas": _platforms(report),
        }

    return app


def _text(field: str, limit: int) -> str | None:
    value = (request.get_json(silent=True) or {}).get(field) or ""
    return (value.strip()[:limit] or None) if isinstance(value, str) else None


def _local(moment) -> str | None:
    """Datas do banco ficam em UTC sem fuso: mostra no horário desta máquina."""
    if not moment:
        return None
    return moment.replace(tzinfo=timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "cliente"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _platforms(report, full: bool = False) -> list[dict[str, Any]]:
    """Situação de cada plataforma na geração. Na lista, lê só o começo de cada arquivo (alguns têm milhares de
    registros); no detalhe, o arquivo inteiro, para mostrar erros e avisos."""
    if not report.run_dir:
        return []
    folder = Path(report.run_dir)
    services = _read_json(folder / "cliente.json").get("servicos") or {}
    platforms = []
    for slug, external in services.items():
        path = folder / f"{slug}.json"
        item: dict[str, Any] = {"plataforma": slug, "nome_na_plataforma": external, "status": "falha", "contagens": {}}
        if full:
            data = _read_json(path)
            issues = data.get("issues") or []
            item.update(status=data.get("status", "falha"), contagens=data.get("counts") or {},
                        erros=[i.get("message") for i in issues if i.get("severity") == "erro"][:5],
                        avisos=[i.get("message") for i in issues if i.get("severity") == "aviso"][:8])
        else:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(4096)
            except OSError:
                head = ""
            status, counts = _STATUS_IN_HEAD.search(head), _COUNTS_IN_HEAD.search(head)
            item["status"] = status.group(1) if status else "falha"
            if counts:
                with contextlib.suppress(ValueError):
                    item["contagens"] = json.loads(counts.group(1))
        platforms.append(item)
    return platforms

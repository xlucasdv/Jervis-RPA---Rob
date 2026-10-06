"""Feature 9.5: saúde da ferramenta, códigos de saída e notificações."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from jervis import cli
from jervis.collectors.models import CollectionResult, Issue
from jervis.config import AppConfig, EmailConfig, NotificationConfig, PlatformConfig, Settings, parse_config
from jervis.credentials import CredentialStore
from jervis.errors import ConfigError, IssueCategory
from jervis.health import STATUS_FILE, compute_health
from jervis.notify import SMTP_SECRET, WEBHOOK_SECRET, Notifier, compose, notification_status
from jervis.runner import Progress, Runner


def ok(name):
    r = CollectionResult(platform=name, kind="sophos")
    r.datasets = {"dispositivos": [{"nome": "PC", "status_agente": "Ativo", "situacao_protecao": "Protegido", "origem": "c"}]}
    r.finished_at = r.started_at
    return r


def failed(name):
    r = CollectionResult(platform=name, kind="sophos")
    r.issues = [Issue("autenticacao", IssueCategory.AUTHENTICATION, "Acesso negado")]
    r.finished_at = r.started_at
    return r


@pytest.fixture
def config(tmp_path):
    settings = Settings(output_dir=str(tmp_path / "output"), report_formats=["html"],
                        audit_file=str(tmp_path / "logs" / "a.jsonl"))
    return AppConfig(settings=settings, platforms={
        n: PlatformConfig(name=n, kind="sophos", url=f"https://{n}.local", enabled=True) for n in ("sophos", "acronis")})


class FakeNotifier:
    def __init__(self, errors=None, when=("parcial", "falha")):
        self.sent, self.errors, self.when = [], errors or {}, when

    def should_notify(self, manifest):
        return notification_status(manifest) in self.when

    def notify(self, manifest, run_dir, force=False):
        self.sent.append(manifest["status"])
        return self.errors


def run(config, results, notifier=None):
    queue = {r.platform: r for r in results}
    runner = Runner(config, store=CredentialStore(environ={}), emit=Progress(lambda line: None),
                    collect=lambda p, s, st, only=None, progress=None: queue[p.name], notifier=notifier or FakeNotifier())
    return runner.run([config.platforms[r.platform] for r in results])


# --- códigos de saída e saúde -------------------------------------------------------------

def test_exit_codes_distinguish_partial_and_failure(config):
    assert run(config, [ok("sophos"), ok("acronis")]).exit_code == 0
    assert run(config, [ok("sophos"), failed("acronis")]).exit_code == 2
    assert run(config, [failed("sophos"), failed("acronis")]).exit_code == 3


def test_health_ok_after_successful_run_and_status_file(config):
    run(config, [ok("sophos"), ok("acronis")])
    status = json.loads((Path(config.settings.output_dir) / STATUS_FILE).read_text(encoding="utf-8"))
    assert status["saude"] == "ok" and status["motivos"] == []
    assert status["plataformas"]["sophos"]["ultimo_status"] == "sucesso"


def test_health_attention_on_partial_and_critical_on_failure(config):
    run(config, [ok("sophos"), ok("acronis")])
    run(config, [ok("sophos"), failed("acronis")])
    health = compute_health(config)
    assert health["saude"] == "atencao" and "parcial: acronis" in health["motivos"][0]
    run(config, [failed("sophos"), failed("acronis")])
    assert compute_health(config)["saude"] == "critico"


def test_health_critical_when_platform_has_no_recent_success(config):
    run(config, [ok("sophos"), ok("acronis")])
    later = datetime.now() + timedelta(hours=30)
    health = compute_health(config, now=later)
    assert health["saude"] == "critico"
    assert any("sophos" in r and "sem coleta bem-sucedida (limite: 26 h)" in r for r in health["motivos"])


def test_health_critical_without_history(config):
    health = compute_health(config)
    assert health["saude"] == "critico" and "Nenhuma execução registrada." in health["motivos"]


def test_cli_status_exit_codes_and_json(config, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["-c", "platforms.yaml", "init"])
    text = (tmp_path / "platforms.yaml").read_text(encoding="utf-8")
    text = text.replace("output_dir: output", f"output_dir: '{config.settings.output_dir}'")
    text = text.replace("enabled: false\n    url: https://central.sophos.com/manage", "enabled: true\n    url: https://central.sophos.com/manage", 1)
    (tmp_path / "platforms.yaml").write_text(text, encoding="utf-8")
    run(config, [ok("sophos"), failed("acronis")])
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "status"]) == 2
    out = capsys.readouterr().out
    assert "Saúde da ferramenta: ATENÇÃO" in out and "sophos" in out
    assert cli.main(["-c", "platforms.yaml", "status", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["saude"] == "atencao"


# --- notificações -----------------------------------------------------------------------

def test_notifies_only_configured_statuses_and_records_failures(config):
    notifier = FakeNotifier()
    run(config, [ok("sophos"), ok("acronis")], notifier)
    assert notifier.sent == []  # sucesso não notifica com when=[parcial, falha]
    run(config, [ok("sophos"), failed("acronis")], notifier)
    assert notifier.sent == ["parcial"]

    broken = FakeNotifier(errors={"email": "SMTPAuthenticationError: senha inválida"})
    summary = run(config, [failed("sophos"), failed("acronis")], broken)
    assert summary.manifest["falhas_notificacao"] == {"email": "SMTPAuthenticationError: senha inválida"}
    assert summary.exit_code == 3  # a falha de notificação não altera o resultado da coleta


def test_compose_message(tmp_path):
    manifest = {"id": "20261006-070000", "origem": "agendamento:diaria", "ambiente": "prod", "status": "parcial",
                "usuario": "EMPRESA\\op", "maquina": "SRV01", "inicio": "2026-10-06T07:00:00-03:00", "duracao_s": 95,
                "plataformas": {"sophos": {"status": "sucesso", "contagens": {"dispositivos": 27}},
                                "acronis": {"status": "falha", "falhas": ["[autenticacao] autenticacao: Acesso negado"]}},
                "consolidado": {"critico": 4, "normal": 70}}
    subject, body = compose(manifest, tmp_path)
    assert subject == "[Jervis3000 prod] PARCIAL — coleta 20261006-070000 (1 de 2 plataforma(s))"
    assert "acronis: FALHA" in body and "erro: [autenticacao] autenticacao: Acesso negado" in body
    assert "Consolidado: critico: 4 | normal: 70" in body and "jervis runs show 20261006-070000" in body


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout):
        self.host, self.port, self.calls, self.message = host, port, [], None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, message):
        self.message = message


def test_email_with_starttls_login_and_report_attachment(tmp_path):
    (tmp_path / "relatorio.html").write_text("<html>relatório</html>", encoding="utf-8")
    store = CredentialStore(environ={})
    store.set_secret(SMTP_SECRET, "senha-smtp")
    cfg = NotificationConfig(email=EmailConfig(smtp_host="smtp.empresa.com", sender="jervis@empresa.com",
                                               recipients=["ti@empresa.com"], username="jervis@empresa.com"))
    errors = Notifier(cfg, store, smtp_factory=FakeSMTP).notify({"id": "r1", "status": "falha", "plataformas": {}}, tmp_path)
    assert errors == {}
    smtp = FakeSMTP.instances[-1]
    assert (smtp.host, smtp.port) == ("smtp.empresa.com", 587)
    assert smtp.calls == ["starttls", ("login", "jervis@empresa.com", "senha-smtp")]
    assert smtp.message["To"] == "ti@empresa.com" and "[Jervis3000] FALHA" in smtp.message["Subject"]
    assert [a.get_filename() for a in smtp.message.iter_attachments()] == ["relatorio.html"]


def test_email_without_saved_password_reports_clear_error(tmp_path):
    cfg = NotificationConfig(email=EmailConfig(smtp_host="smtp", sender="a@b.com", recipients=["c@d.com"], username="u"))
    errors = Notifier(cfg, CredentialStore(environ={}), smtp_factory=FakeSMTP).notify({"id": "r", "status": "falha", "plataformas": {}}, tmp_path)
    assert "jervis notify set-smtp-password" in errors["email"]


class FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize("fmt", ["teams", "slack", "json"])
def test_webhook_payloads(tmp_path, fmt):
    store = CredentialStore(environ={})
    store.set_secret(WEBHOOK_SECRET, "https://empresa.webhook.office.com/abc")
    sent = []
    cfg = NotificationConfig(webhook=True, webhook_format=fmt)
    notifier = Notifier(cfg, store, urlopen=lambda req, timeout: sent.append(req) or FakeResponse())
    assert notifier.notify({"id": "r1", "status": "parcial", "plataformas": {}}, tmp_path) == {}
    payload = json.loads(sent[0].data)
    assert sent[0].full_url == "https://empresa.webhook.office.com/abc"
    if fmt == "teams":
        assert payload["attachments"][0]["content"]["type"] == "AdaptiveCard"
    elif fmt == "slack":
        assert payload["text"].startswith("*[Jervis3000] PARCIAL")
    else:
        assert payload["status"] == "parcial" and payload["execucao"]["id"] == "r1"


@pytest.mark.parametrize(
    "notifications, message",
    [({"when": ["sempre"], "webhook": True}, "when"),
     ({"email": {"smtp_host": "s", "sender": "invalido", "recipients": ["a@b.com"]}}, "inválido"),
     ({"email": {"smtp_host": "s"}}, "smtp_host, sender e recipients"),
     ({"when": ["falha"]}, "configure 'email'"),
     ({"webhook": True, "webhook_format": "discord"}, "webhook_format")],
)
def test_notification_config_validation(notifications, message):
    with pytest.raises(ConfigError, match=message):
        parse_config({"platforms": {}, "notifications": notifications})


def test_cli_notify_test_and_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["-c", "platforms.yaml", "init"])
    with open(tmp_path / "platforms.yaml", "a", encoding="utf-8") as fh:
        fh.write("\nnotifications:\n  when: [falha]\n  webhook: true\n  webhook_format: json\n")
    answers = iter(["https://hooks.empresa.com/x"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["-c", "platforms.yaml", "notify", "set-webhook"]) == 0
    sent = []
    monkeypatch.setattr("jervis.notify.urllib.request.urlopen", lambda req, timeout: sent.append(req) or FakeResponse())
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "notify", "test"]) == 0
    assert "webhook: enviado" in capsys.readouterr().out
    assert json.loads(sent[0].data)["execucao"]["id"] == "teste"
    assert "https://hooks.empresa.com/x" not in (tmp_path / "platforms.yaml").read_text(encoding="utf-8")

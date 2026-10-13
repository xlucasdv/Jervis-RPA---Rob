"""Notificação do resultado das execuções (Feature 9.5): e-mail e webhook (Teams, Slack ou JSON).

Segredos não ficam no arquivo de configuração: a senha do SMTP e a URL do webhook (que contém
um token) são guardadas no cofre do sistema com ``jervis notify set-smtp-password`` e
``jervis notify set-webhook``. Uma falha ao notificar nunca interrompe a execução: é
registrada no log, em ``execucao.json`` e na auditoria.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable

from jervis.config import NotificationConfig
from jervis.credentials import CredentialStore
from jervis.errors import JervisError

log = logging.getLogger(__name__)

SMTP_SECRET = "notificacao:smtp"
WEBHOOK_SECRET = "notificacao:webhook"
MAX_ATTACHMENT = 10 * 1024 * 1024

_LABEL = {"sucesso": "SUCESSO", "parcial": "PARCIAL", "falha": "FALHA"}
_TEAMS_COLOR = {"sucesso": "Good", "parcial": "Warning", "falha": "Attention"}


class NotificationError(JervisError):
    """Falha ao enviar uma notificação."""


def notification_status(manifest: dict[str, Any]) -> str:
    """Situação que decide se notifica: erro conta como falha; relatório que falhou, como parcial."""
    if manifest.get("estado") == "erro" or manifest.get("status") == "falha":
        return "falha"
    if manifest.get("status") == "parcial" or manifest.get("falhas_relatorio") or manifest.get("falhas_pos_coleta"):
        return "parcial"
    return "sucesso"


def compose(manifest: dict[str, Any], run_dir: Path) -> tuple[str, str]:
    """Assunto e texto da notificação."""
    status = notification_status(manifest)
    platforms = manifest.get("plataformas") or {}
    ok = sum(1 for p in platforms.values() if p.get("status") == "sucesso")
    env = f" {manifest['ambiente']}" if manifest.get("ambiente") else ""
    subject = f"[Jervis3000{env}] {_LABEL[status]} — coleta {manifest['id']} ({ok} de {len(platforms)} plataforma(s))"
    lines = [
        f"Execução {manifest['id']} ({manifest.get('origem')}{', ambiente ' + manifest['ambiente'] if manifest.get('ambiente') else ''}): {_LABEL[status]}",
        f"Iniciada por {manifest.get('usuario', '—')} em {manifest.get('maquina', '—')}; "
        f"início {manifest.get('inicio') or '—'}, duração {manifest.get('duracao_s') or '—'} s.",
        "",
        "Plataformas:",
    ]
    for name, info in platforms.items():
        counts = " | ".join(f"{k}: {v}" for k, v in (info.get("contagens") or {}).items())
        lines.append(f"  - {name}: {_LABEL.get(info.get('status'), info.get('estado', '?'))}" + (f" ({counts})" if counts else ""))
        lines += [f"      erro: {f}" for f in info.get("falhas") or []]
        lines += [f"      aviso: {w}" for w in info.get("avisos") or []]
    if manifest.get("erro"):
        lines += ["", f"Erro inesperado: {manifest['erro']}"]
    if manifest.get("consolidado"):
        lines += ["", "Consolidado: " + " | ".join(f"{k}: {v}" for k, v in manifest["consolidado"].items())]
    for fmt, error in (manifest.get("falhas_relatorio") or {}).items():
        lines.append(f"Relatório {fmt.upper()} não gerado: {error}")
    report = run_dir / "relatorio.html"
    lines += ["", f"Relatório: {report.resolve() if report.exists() else '(não gerado)'}",
              f"Detalhes: jervis runs show {manifest['id']}"]
    return subject, "\n".join(lines)


class Notifier:
    def __init__(
        self,
        config: NotificationConfig | None,
        store: CredentialStore,
        smtp_factory: Callable[..., smtplib.SMTP] | None = None,
        urlopen: Callable[..., Any] | None = None,
    ):
        self.config = config
        self.store = store
        self._smtp_factory = smtp_factory
        self._urlopen = urlopen or (lambda request, timeout: urllib.request.urlopen(request, timeout=timeout))

    def should_notify(self, manifest: dict[str, Any]) -> bool:
        return bool(self.config) and notification_status(manifest) in self.config.when

    def notify(self, manifest: dict[str, Any], run_dir: Path, force: bool = False) -> dict[str, str]:
        """Envia pelos canais configurados. Devolve {canal: erro} das falhas (vazio = tudo enviado)."""
        if not self.config or not (force or self.should_notify(manifest)):
            return {}
        subject, body = compose(manifest, run_dir)
        errors = {}
        if self.config.email:
            try:
                self._send_email(subject, body, run_dir)
            except (OSError, smtplib.SMTPException, NotificationError) as exc:
                errors["email"] = f"{type(exc).__name__}: {exc}"
        if self.config.webhook:
            try:
                self._send_webhook(subject, body, manifest)
            except (OSError, NotificationError) as exc:
                errors["webhook"] = f"{type(exc).__name__}: {exc}"
        for channel, error in errors.items():
            log.error("Falha ao notificar por %s: %s", channel, error)
        return errors

    def channels(self) -> list[str]:
        """Canais configurados (e-mail e/ou webhook)."""
        if not self.config:
            return []
        return [name for name, on in (("email", self.config.email), ("webhook", self.config.webhook)) if on]

    def send_message(self, subject: str, body: str, status: str = "sucesso", data: dict[str, Any] | None = None) -> dict[str, str]:
        """Aviso avulso (ex.: fechamento mensal) por todos os canais configurados, sem o filtro de ``when``.
        Devolve {canal: erro} das falhas; sem canais configurados, {"notificacao": motivo}."""
        if not self.channels():
            return {"notificacao": "nenhum canal configurado (seção notifications: webhook e/ou email)"}
        errors = {}
        if self.config.email:
            try:
                self._send_email(subject, body, None)
            except (OSError, smtplib.SMTPException, NotificationError) as exc:
                errors["email"] = f"{type(exc).__name__}: {exc}"
        if self.config.webhook:
            try:
                self._post_webhook(self._payload(subject, body, status, data or {"assunto": subject, "texto": body}))
            except (OSError, NotificationError) as exc:
                errors["webhook"] = f"{type(exc).__name__}: {exc}"
        for channel, error in errors.items():
            log.error("Falha ao notificar por %s: %s", channel, error)
        return errors

    # --- canais -----------------------------------------------------------------------

    def _send_email(self, subject: str, body: str, run_dir: Path | None) -> None:
        cfg = self.config.email
        message = EmailMessage()
        message["Subject"], message["From"], message["To"] = subject, cfg.sender, ", ".join(cfg.recipients)
        message.set_content(body)
        report = run_dir / "relatorio.html" if run_dir else None
        if cfg.attach_report and report and report.exists() and report.stat().st_size <= MAX_ATTACHMENT:
            message.add_attachment(report.read_bytes(), maintype="text", subtype="html", filename=report.name)
        factory = self._smtp_factory or (smtplib.SMTP_SSL if cfg.ssl else smtplib.SMTP)
        with factory(cfg.smtp_host, cfg.smtp_port, timeout=30) as smtp:
            if cfg.starttls and not cfg.ssl:
                smtp.starttls(context=ssl.create_default_context())
            if cfg.username:
                password = self.store.get_secret(SMTP_SECRET)
                if not password:
                    raise NotificationError("Senha do SMTP não cadastrada: use 'jervis notify set-smtp-password'.")
                smtp.login(cfg.username, password)
            smtp.send_message(message)

    def _send_webhook(self, subject: str, body: str, manifest: dict[str, Any]) -> None:
        self._post_webhook(self._webhook_payload(subject, body, manifest))

    def _post_webhook(self, payload: dict[str, Any]) -> None:
        url = self.store.get_secret(WEBHOOK_SECRET)
        if not url:
            raise NotificationError("URL do webhook não cadastrada: use 'jervis notify set-webhook'.")
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self._urlopen(request, timeout=30) as response:
            if response.status >= 300:
                raise NotificationError(f"Webhook respondeu HTTP {response.status}.")

    def _webhook_payload(self, subject: str, body: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return self._payload(subject, body, notification_status(manifest), {"execucao": manifest})

    def _payload(self, subject: str, body: str, status: str, data: dict[str, Any]) -> dict[str, Any]:
        fmt = self.config.webhook_format
        if fmt == "slack":
            return {"text": f"*{subject}*\n```{body}```"}
        if fmt == "json":
            return {"assunto": subject, "status": status, **data}
        # Teams (fluxo "Workflows" com Adaptive Card; os conectores antigos do Office 365 foram descontinuados).
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard", "version": "1.4",
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "body": [
                        {"type": "TextBlock", "text": subject, "weight": "Bolder", "wrap": True, "color": _TEAMS_COLOR[status]},
                        {"type": "TextBlock", "text": body.replace("\n", "\n\n"), "wrap": True, "fontType": "Monospace", "size": "Small"},
                    ],
                },
            }],
        }

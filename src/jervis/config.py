"""Cadastro das plataformas e parâmetros gerais (arquivo YAML).

O arquivo guarda apenas dados NÃO sensíveis (URLs, ambiente, ativação,
seletores). Credenciais ficam no cofre do sistema ou em variáveis de ambiente
(ver ``jervis.credentials``); a carga recusa arquivos que tentem armazená-las.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from dataclasses import dataclass, field, fields
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from jervis.auth.profiles import SELECTOR_FIELDS, SUPPORTED_KINDS
from jervis.errors import ConfigError
from jervis.fileutil import replace

ENV_CONFIG_PATH = "JERVIS_CONFIG"
ENV_ENVIRONMENT = "JERVIS_ENV"
ENVIRONMENT_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,19}")

# Em um ambiente (--env hml), estes caminhos ganham o subdiretório do ambiente, a menos que o
# arquivo do ambiente defina outro valor: histórico, logs e auditoria nunca se misturam.
_ENV_APPEND = ("output_dir",)  # output -> output/hml
_ENV_INSERT = ("log_file", "audit_file", "screenshot_dir")  # logs/jervis.log -> logs/hml/jervis.log
DEFAULT_CONFIG_PATH = Path("config") / "platforms.yaml"

MFA_METHODS = ("none", "totp", "prompt")
REPORT_FORMATS = ("html", "xlsx", "csv", "pdf")
BROWSERS = ("edge", "chrome", "firefox")

# Chaves que indicam tentativa de gravar credenciais no arquivo de configuração.
FORBIDDEN_KEYS = frozenset(
    {"password", "senha", "username", "usuario", "user", "login", "token", "secret", "totp_secret", "api_key"}
)


@dataclass
class Settings:
    browser: str = "edge"
    # Caminho de um driver já aprovado (msedgedriver.exe, chromedriver.exe, geckodriver.exe).
    # Vazio: o Selenium Manager baixa o driver automaticamente.
    driver_path: str = ""
    # Edge: confere o driver antes de cada coleta e baixa o da versão do navegador instalado
    # (jervis driver update). Sem driver_path, usa drivers/msedgedriver.exe.
    driver_auto_update: bool = False
    # Pasta de um perfil próprio do navegador (ex.: perfil_navegador): janela normal que guarda cookies e
    # sessões entre execuções (ex.: "Confiar neste navegador" dispensa o MFA). Vazio: janela anônima e limpa.
    browser_profile: str = ""
    headless: bool = True
    page_load_timeout: int = 60
    login_timeout: int = 30
    collect_timeout: int = 30
    log_file: str = "logs/jervis.log"
    output_dir: str = "output"
    screenshot_on_failure: bool = False
    screenshot_dir: str = "logs/screenshots"
    # Consolidação: endpoint sem comunicação há mais dias = indisponível;
    # disponibilidade (Zabbix) abaixo deste percentual = crítico.
    stale_device_days: int = 7
    critical_availability_pct: float = 95.0
    # Relatórios gerados ao fim de cada coleta (html, xlsx, csv, pdf).
    report_formats: list[str] = field(default_factory=lambda: ["html", "xlsx", "csv", "pdf"])
    report_title: str = "Relatório geral de TI"
    # Identidade visual dos relatórios (padrão de apresentação): nome da empresa e logo (PNG/SVG/JPG; vazio = ícone + nome).
    report_company: str = "Contego Security"
    report_logo: str = ""
    # Auditoria e retenção (Épico 8).
    audit_file: str = "logs/auditoria.jsonl"
    retention_days: int = 90  # pastas de execução mais antigas são removidas (0 = nunca)
    incomplete_drop_pct: int = 50  # queda de registros, frente à última coleta, sinalizada como dados incompletos
    # Saúde da ferramenta: plataforma ativa sem coleta bem-sucedida há mais horas = crítico.
    max_hours_without_success: int = 26


@dataclass
class PlatformConfig:
    name: str
    kind: str
    url: str = ""
    enabled: bool = False
    environment: str = "producao"
    description: str = ""
    mfa: str = "none"
    login_timeout: int | None = None
    selectors: dict[str, list[str]] = field(default_factory=dict)
    # Parâmetros livres consumidos pelas etapas de coleta.
    params: dict[str, Any] = field(default_factory=dict)


FREQUENCIES = ("daily", "weekly", "hourly", "monthly")
# coleta: coleta pelo navegador das plataformas ativas; relatorios_clientes: fechamento mensal dos relatórios por
# cliente (API), gerados para o mês anterior e deixados pendentes de revisão
SCHEDULE_TASKS = ("coleta", "relatorios_clientes")
FIRST_BUSINESS_DAY = "primeiro_dia_util"  # monthly: em vez de um número, o primeiro dia útil do mês
_DAY_ALIASES = {"primeiro_dia_util": FIRST_BUSINESS_DAY, "primeiro dia util": FIRST_BUSINESS_DAY,
                "primeiro dia útil": FIRST_BUSINESS_DAY, "first_business_day": FIRST_BUSINESS_DAY}
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_FREQUENCY_ALIASES = {"diaria": "daily", "diario": "daily", "semanal": "weekly", "horas": "hourly", "a_cada_horas": "hourly",
                      "mensal": "monthly"}
_WEEKDAY_ALIASES = {"seg": "mon", "ter": "tue", "qua": "wed", "qui": "thu", "sex": "fri", "sab": "sat", "sáb": "sat", "dom": "sun"}


@dataclass
class ScheduleConfig:
    name: str
    frequency: str  # daily | weekly | hourly
    enabled: bool = True
    times: list[str] = field(default_factory=list)  # daily/weekly: horários "HH:MM"
    days: list[str] = field(default_factory=list)  # weekly: mon..sun (ou seg..dom)
    every_hours: int | None = None  # hourly: intervalo em horas
    start: str = "00:00"  # hourly: horário de referência do dia
    day: int | str | None = None  # monthly: dia do mês (1 a 28) ou "primeiro_dia_util"
    task: str = "coleta"  # SCHEDULE_TASKS
    platforms: list[str] = field(default_factory=list)  # vazio = todas as ativas
    retries: int = 1  # reprocessamentos automáticos das falhas
    retry_delay_minutes: int = 10


NOTIFY_WHEN = ("sucesso", "parcial", "falha")
WEBHOOK_FORMATS = ("teams", "slack", "json")


@dataclass
class EmailConfig:
    smtp_host: str
    sender: str
    recipients: list[str]
    smtp_port: int = 587
    starttls: bool = True
    ssl: bool = False
    username: str | None = None  # senha: jervis notify set-smtp-password
    attach_report: bool = True


@dataclass
class NotificationConfig:
    when: list[str] = field(default_factory=lambda: ["parcial", "falha"])
    email: EmailConfig | None = None
    webhook: bool = False  # URL: jervis notify set-webhook
    webhook_format: str = "teams"


@dataclass
class DatabaseConfig:
    """Conexão com o MySQL. Usuário e senha ficam no cofre (jervis db set-credentials) ou em
    JERVIS_DATABASE_USERNAME / JERVIS_DATABASE_PASSWORD, nunca neste arquivo."""

    host: str = "127.0.0.1"
    port: int = 3306
    name: str = "jervis3000"
    connect_timeout: int = 10


WEB_ROLES = ("leitura", "revisor", "admin")
# Rede interna e VPN (faixas privadas) e a própria máquina
DEFAULT_WEB_NETWORKS = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


@dataclass
class WebConfig:
    """Interface web da equipe (jervis web serve): login com a conta Microsoft 365 (aplicativo no Entra ID). O
    segredo do aplicativo fica no cofre (jervis web set-secret), nunca neste arquivo."""

    public_url: str = ""  # endereço que a equipe abre (https://<máquina>:8443); o login volta em <public_url>/auth/callback
    tenant_id: str = ""   # ID do diretório (locatário) no Entra ID
    client_id: str = ""   # ID do aplicativo (cliente) no Entra ID
    host: str = "0.0.0.0"
    port: int = 8443
    cert_file: str = "config/web/jervis-web.pem"
    key_file: str = "config/web/jervis-web.key"
    allowed_networks: list[str] = field(default_factory=lambda: list(DEFAULT_WEB_NETWORKS))
    session_hours: int = 8

    @property
    def redirect_uri(self) -> str:
        return f"{self.public_url.rstrip('/')}/auth/callback"

    def missing(self) -> list[str]:
        """O que falta preencher para o login funcionar."""
        return [name for name in ("public_url", "tenant_id", "client_id") if not getattr(self, name)]


@dataclass
class AppConfig:
    settings: Settings
    platforms: dict[str, PlatformConfig]
    path: Path | None = None
    schedules: dict[str, ScheduleConfig] = field(default_factory=dict)
    notifications: NotificationConfig | None = None
    database: DatabaseConfig | None = None  # None = sem banco (as tabelas não são criadas)
    web: WebConfig | None = None  # None = interface web não configurada
    environment: str | None = None  # ex.: "hml"; None = configuração base
    overlay_path: Path | None = None  # arquivo do ambiente (platforms.<ambiente>.yaml)
    base_raw: dict[str, Any] | None = field(default=None, repr=False)  # conteúdo do arquivo base, para gravar só diferenças

    def get(self, name: str) -> PlatformConfig:
        try:
            return self.platforms[name]
        except KeyError:
            available = ", ".join(sorted(self.platforms)) or "nenhuma"
            raise ConfigError(f"Plataforma '{name}' não cadastrada. Cadastradas: {available}.") from None

    def enabled_platforms(self) -> list[PlatformConfig]:
        return [p for p in self.platforms.values() if p.enabled]


def resolve_config_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path)
    if env := os.environ.get(ENV_CONFIG_PATH):
        return Path(env)
    return DEFAULT_CONFIG_PATH


def validate_url(url: str, platform: str = "") -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        where = f" da plataforma '{platform}'" if platform else ""
        raise ConfigError(f"URL inválida{where}: '{url}'. Informe o endereço completo, ex.: https://zabbix.empresa.com.br")
    return url


def is_insecure_url(url: str) -> bool:
    return urlparse(url).scheme == "http"


def template_text() -> str:
    return resources.files("jervis").joinpath("templates/platforms.example.yaml").read_text(encoding="utf-8")


def resolve_environment(env: str | None = None) -> str | None:
    env = env or os.environ.get(ENV_ENVIRONMENT) or None
    if env is not None and not ENVIRONMENT_NAME.fullmatch(env):
        raise ConfigError(f"Nome de ambiente inválido '{env}': use letras minúsculas, números, '-' ou '_' (ex.: dev, hml, prod).")
    return env


def overlay_path_for(base: Path, env: str) -> Path:
    return base.with_name(f"{base.stem}.{env}{base.suffix}")


_OVERLAY_TEMPLATE = """# Ambiente "{env}": sobrescreve {base}. Inclua só o que muda neste ambiente.
#
# Separados automaticamente por ambiente: saída (output/{env}), logs, auditoria e histórico
# (logs/{env}), credenciais (cofre "jervis3000-{env}") e tarefas agendadas (Jervis3000\\{env}).
# Cadastre as credenciais deste ambiente com: jervis --env {env} credentials set <plataforma>

settings:
  headless: true
#  report_title: Relatório geral de TI ({env})

platforms: {{}}
#  zabbix:
#    url: https://zabbix-{env}.empresa.com.br/index.php
#    enabled: true
#    environment: {env}

# schedules: {{}}   # agendamentos deste ambiente (substituem os da base, por nome)
"""


def init_config(path: str | Path | None = None, force: bool = False, env: str | None = None) -> Path:
    """Cria o arquivo de configuração a partir do modelo comentado (ou o arquivo de um ambiente)."""
    target = resolve_config_path(path)
    if env:
        if not target.exists():
            raise ConfigError(f"Crie primeiro a configuração base ({target}) com 'jervis init'.")
        overlay = overlay_path_for(target, env)
        if overlay.exists() and not force:
            raise ConfigError(f"O arquivo {overlay} já existe. Use --force para sobrescrever.")
        overlay.write_text(_OVERLAY_TEMPLATE.format(env=env, base=target.name), encoding="utf-8")
        return overlay
    if target.exists() and not force:
        raise ConfigError(f"O arquivo {target} já existe. Use --force para sobrescrever.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template_text(), encoding="utf-8")
    return target


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Erro de sintaxe em {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} deve conter um mapeamento YAML.")
    return raw


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Mapeamentos são combinados recursivamente; listas e valores simples são substituídos."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _environment_paths(settings: dict[str, Any], overlay_settings: dict[str, Any], env: str) -> dict[str, Any]:
    settings = dict(settings)
    defaults = Settings()
    for key in _ENV_APPEND + _ENV_INSERT:
        if key in overlay_settings:
            continue
        current = Path(str(settings.get(key, getattr(defaults, key))))
        settings[key] = str(current / env if key in _ENV_APPEND else current.parent / env / current.name).replace("\\", "/")
    return settings


def load_config(path: str | Path | None = None, env: str | None = None) -> AppConfig:
    target = resolve_config_path(path)
    if not target.exists():
        raise ConfigError(f"Arquivo de configuração não encontrado: {target}. Execute 'jervis init' para criá-lo.")
    base_raw = _read_yaml(target)
    env = resolve_environment(env)
    raw, overlay = base_raw, None
    if env:
        overlay = overlay_path_for(target, env)
        if not overlay.exists():
            raise ConfigError(f"Arquivo do ambiente '{env}' não encontrado: {overlay}. Crie-o com 'jervis --env {env} init'.")
        overlay_raw = _read_yaml(overlay)
        raw = deep_merge(base_raw, overlay_raw)
        raw["settings"] = _environment_paths(raw.get("settings") or {}, overlay_raw.get("settings") or {}, env)
    try:
        config = parse_config(raw)
    except ConfigError as exc:
        where = f"{target}" + (f" + {overlay}" if overlay else "")
        raise ConfigError(f"{exc} (em {where})") from exc
    config.path, config.environment, config.overlay_path, config.base_raw = target, env, overlay, base_raw
    return config


def parse_config(raw: Any) -> AppConfig:
    if not isinstance(raw, dict):
        raise ConfigError("O arquivo de configuração deve conter um mapeamento YAML.")
    _reject_unknown(raw, {"settings", "platforms", "schedules", "notifications", "database", "web"}, "raiz do arquivo")
    settings = _parse_settings(raw.get("settings") or {})
    platforms_raw = raw.get("platforms") or {}
    if not isinstance(platforms_raw, dict):
        raise ConfigError("'platforms' deve ser um mapeamento nome → configuração.")
    platforms = {str(name): _parse_platform(str(name), data or {}) for name, data in platforms_raw.items()}
    schedules_raw = raw.get("schedules") or {}
    if not isinstance(schedules_raw, dict):
        raise ConfigError("'schedules' deve ser um mapeamento nome → agendamento.")
    schedules = {str(name): _parse_schedule(str(name), data or {}, platforms) for name, data in schedules_raw.items()}
    notifications = _parse_notifications(raw["notifications"]) if raw.get("notifications") else None
    database = _parse_database(raw["database"]) if raw.get("database") else None
    web = _parse_web(raw["web"]) if raw.get("web") else None
    return AppConfig(settings=settings, platforms=platforms, schedules=schedules, notifications=notifications,
                     database=database, web=web)


def _parse_web(data: Any) -> WebConfig:
    where = "web"
    if not isinstance(data, dict):
        raise ConfigError(f"'{where}' deve ser um mapeamento (public_url, tenant_id, client_id...).")
    _reject_unknown(data, {f.name for f in fields(WebConfig)}, where)
    web = WebConfig(**{k: ("" if v is None else v) for k, v in data.items()})
    for name in ("public_url", "tenant_id", "client_id", "host", "cert_file", "key_file"):
        if not isinstance(getattr(web, name), str):
            raise ConfigError(f"{where}.{name} deve ser um texto.")
    web.public_url = web.public_url.strip().rstrip("/")
    if web.public_url:
        parsed = urlparse(web.public_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/"):
            raise ConfigError(f"{where}.public_url deve ser o endereço https da interface, ex.: https://pc-ti:8443 "
                              "(o login da Microsoft só volta para endereços https).")
    for name in ("tenant_id", "client_id"):
        value = getattr(web, name).strip()
        if value and not _GUID.fullmatch(value):
            raise ConfigError(f"{where}.{name} deve ser o identificador (GUID) mostrado no Entra ID, "
                              "ex.: 0f8fad5b-d9cb-469f-a165-70867728950e.")
        setattr(web, name, value.lower())
    if not isinstance(web.port, int) or isinstance(web.port, bool) or not 0 < web.port < 65536:
        raise ConfigError(f"{where}.port deve ser uma porta entre 1 e 65535.")
    if not isinstance(web.session_hours, int) or isinstance(web.session_hours, bool) or not 1 <= web.session_hours <= 24:
        raise ConfigError(f"{where}.session_hours deve ser de 1 a 24 (horas até pedir o login de novo).")
    networks = web.allowed_networks if isinstance(web.allowed_networks, list) else [web.allowed_networks]
    if not networks:
        raise ConfigError(f"{where}.allowed_networks: informe ao menos uma rede (ex.: 192.168.0.0/16).")
    for network in networks:
        try:
            ipaddress.ip_network(str(network), strict=False)
        except ValueError as exc:
            raise ConfigError(f"{where}.allowed_networks: '{network}' não é uma rede válida (ex.: 10.0.0.0/8).") from exc
    web.allowed_networks = [str(n) for n in networks]
    return web


_DB_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")


def _parse_database(data: Any) -> DatabaseConfig:
    where = "database"
    if not isinstance(data, dict):
        raise ConfigError(f"'{where}' deve ser um mapeamento (host, port, name).")
    _reject_unknown(data, {f.name for f in fields(DatabaseConfig)}, where)
    db = DatabaseConfig(**data)
    if not isinstance(db.host, str) or not db.host.strip():
        raise ConfigError(f"{where}.host deve ser o endereço do servidor MySQL.")
    if not isinstance(db.port, int) or isinstance(db.port, bool) or not 0 < db.port < 65536:
        raise ConfigError(f"{where}.port deve ser uma porta entre 1 e 65535.")
    if not isinstance(db.name, str) or not _DB_NAME.fullmatch(db.name):
        raise ConfigError(f"{where}.name deve ter só letras, números e '_' (até 64 caracteres).")
    if not isinstance(db.connect_timeout, int) or isinstance(db.connect_timeout, bool) or db.connect_timeout <= 0:
        raise ConfigError(f"{where}.connect_timeout deve ser um inteiro positivo (segundos).")
    return db


_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _parse_notifications(data: Any) -> NotificationConfig:
    where = "notifications"
    if not isinstance(data, dict):
        raise ConfigError(f"'{where}' deve ser um mapeamento.")
    _reject_unknown(data, {f.name for f in fields(NotificationConfig)}, where)
    data = dict(data)
    email_raw = data.pop("email", None)
    config = NotificationConfig(**data)
    if not isinstance(config.when, list) or not config.when or any(w not in NOTIFY_WHEN for w in config.when):
        raise ConfigError(f"{where}.when deve ser uma lista com: {', '.join(NOTIFY_WHEN)}.")
    if config.webhook_format not in WEBHOOK_FORMATS:
        raise ConfigError(f"{where}.webhook_format deve ser um de: {', '.join(WEBHOOK_FORMATS)}.")
    if email_raw:
        if not isinstance(email_raw, dict):
            raise ConfigError(f"{where}.email deve ser um mapeamento.")
        _reject_unknown(email_raw, {f.name for f in fields(EmailConfig)}, f"{where}.email")
        try:
            email = EmailConfig(**email_raw)
        except TypeError as exc:
            raise ConfigError(f"{where}.email: informe smtp_host, sender e recipients.") from exc
        recipients = email.recipients if isinstance(email.recipients, list) else [email.recipients]
        bad = [a for a in [email.sender, *recipients] if not isinstance(a, str) or not _EMAIL.fullmatch(a)]
        if bad or not recipients:
            raise ConfigError(f"{where}.email: endereço(s) inválido(s): {', '.join(map(str, bad)) or 'nenhum destinatário'}.")
        email.recipients = recipients
        if not isinstance(email.smtp_port, int) or not 0 < email.smtp_port < 65536:
            raise ConfigError(f"{where}.email.smtp_port inválida.")
        config.email = email
    if not config.email and not config.webhook:
        raise ConfigError(f"{where}: configure 'email' e/ou 'webhook: true'.")
    return config


def parse_time(value: Any, where: str) -> str:
    """'07:00' → '07:00'. Aceita também 420: o YAML lê 07:00 sem aspas como minutos (sexagesimal)."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 24 * 60:
        return f"{value // 60:02d}:{value % 60:02d}"
    if isinstance(value, str):
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", value.strip())
        if m and int(m.group(1)) < 24 and int(m.group(2)) < 60:
            return f"{int(m.group(1)):02d}:{m.group(2)}"
    raise ConfigError(f"{where}: horário inválido '{value}'. Use HH:MM, ex.: \"07:30\".")


def _parse_schedule(name: str, data: Any, platforms: dict[str, PlatformConfig]) -> ScheduleConfig:
    where = f"schedules.{name}"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ConfigError(f"Nome de agendamento inválido '{name}': use letras, números, '-' ou '_'.")
    if not isinstance(data, dict):
        raise ConfigError(f"'{where}' deve ser um mapeamento.")
    _reject_unknown(data, {f.name for f in fields(ScheduleConfig)} - {"name"}, where)
    data = dict(data)
    frequency = str(data.pop("frequency", "")).lower()
    frequency = _FREQUENCY_ALIASES.get(frequency, frequency)
    if frequency not in FREQUENCIES:
        raise ConfigError(f"{where}.frequency deve ser daily, weekly, hourly ou monthly (diaria, semanal, horas, mensal).")
    schedule = ScheduleConfig(name=name, frequency=frequency, **data)

    times = schedule.times if isinstance(schedule.times, list) else [schedule.times]
    schedule.times = sorted({parse_time(t, f"{where}.times") for t in times})
    schedule.start = parse_time(schedule.start, f"{where}.start")
    days = schedule.days if isinstance(schedule.days, list) else [schedule.days]
    schedule.days = [_WEEKDAY_ALIASES.get(str(d).lower(), str(d).lower()) for d in days]

    if schedule.task not in SCHEDULE_TASKS:
        raise ConfigError(f"{where}.task deve ser {' ou '.join(SCHEDULE_TASKS)}.")
    if schedule.task == "relatorios_clientes" and schedule.platforms:
        raise ConfigError(f"{where}.platforms não vale para task: relatorios_clientes (os serviços vêm do cadastro de cada cliente).")
    if frequency == "monthly":
        if isinstance(schedule.day, str):
            schedule.day = _DAY_ALIASES.get(schedule.day.strip().lower(), schedule.day)
        if schedule.day != FIRST_BUSINESS_DAY and (
                not isinstance(schedule.day, int) or isinstance(schedule.day, bool) or not 1 <= schedule.day <= 28):
            raise ConfigError(f"{where}.day deve ser um inteiro entre 1 e 28 (dia do mês) ou {FIRST_BUSINESS_DAY}.")
    elif schedule.day is not None:
        raise ConfigError(f"{where}.day só vale para frequency: monthly.")
    if frequency in ("daily", "weekly", "monthly") and not schedule.times:
        raise ConfigError(f"{where}.times: informe ao menos um horário (ex.: [\"07:00\"]).")
    if frequency == "weekly":
        bad = [d for d in schedule.days if d not in WEEKDAYS]
        if not schedule.days or bad:
            raise ConfigError(f"{where}.days: informe dias entre {', '.join(WEEKDAYS)} (ou seg..dom).")
        schedule.days = [d for d in WEEKDAYS if d in schedule.days]
    if frequency == "hourly":
        if not isinstance(schedule.every_hours, int) or isinstance(schedule.every_hours, bool) or not 1 <= schedule.every_hours <= 23:
            raise ConfigError(f"{where}.every_hours deve ser um inteiro entre 1 e 23.")
    unknown = [p for p in schedule.platforms if p not in platforms]
    if unknown:
        raise ConfigError(f"{where}.platforms: plataforma(s) não cadastrada(s): {', '.join(unknown)}.")
    for key in ("retries", "retry_delay_minutes"):
        value = getattr(schedule, key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ConfigError(f"{where}.{key} deve ser um inteiro maior ou igual a zero.")
    return schedule


def _reject_unknown(data: dict, allowed: set[str], where: str) -> None:
    secret_keys = sorted(k for k in data if str(k).lower() in FORBIDDEN_KEYS)
    if secret_keys:
        raise ConfigError(
            f"Credenciais não podem ser gravadas no arquivo de configuração ({where}: {', '.join(secret_keys)}). "
            "Remova essas chaves e use 'jervis credentials set <plataforma>' ou variáveis de ambiente."
        )
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        raise ConfigError(f"Chave(s) desconhecida(s) em {where}: {', '.join(unknown)}. Válidas: {', '.join(sorted(allowed))}.")


def _parse_settings(data: Any) -> Settings:
    if not isinstance(data, dict):
        raise ConfigError("'settings' deve ser um mapeamento.")
    _reject_unknown(data, {f.name for f in fields(Settings)}, "settings")
    settings = Settings(**data)
    if settings.browser not in BROWSERS:
        raise ConfigError(f"Navegador '{settings.browser}' não suportado. Opções: {', '.join(BROWSERS)}.")
    for name in ("page_load_timeout", "login_timeout", "collect_timeout"):
        if not isinstance(getattr(settings, name), int) or getattr(settings, name) <= 0:
            raise ConfigError(f"settings.{name} deve ser um inteiro positivo (segundos).")
    if not isinstance(settings.stale_device_days, int) or settings.stale_device_days <= 0:
        raise ConfigError("settings.stale_device_days deve ser um inteiro positivo (dias).")
    pct = settings.critical_availability_pct
    if not isinstance(pct, (int, float)) or isinstance(pct, bool) or not 0 < pct <= 100:
        raise ConfigError("settings.critical_availability_pct deve ser um percentual entre 0 e 100.")
    formats = settings.report_formats
    if not isinstance(formats, list) or any(f not in REPORT_FORMATS for f in formats):
        raise ConfigError(f"settings.report_formats deve ser uma lista com: {', '.join(REPORT_FORMATS)}.")
    for name, upper in (("retention_days", None), ("incomplete_drop_pct", 100), ("max_hours_without_success", None)):
        value = getattr(settings, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or (upper and value > upper):
            raise ConfigError(f"settings.{name} deve ser um inteiro entre 0 e {upper or 'N'}.")
    for name in ("driver_auto_update", "headless", "screenshot_on_failure"):
        if not isinstance(getattr(settings, name), bool):
            raise ConfigError(f"settings.{name} deve ser true ou false.")
    if not isinstance(settings.browser_profile, str):
        raise ConfigError("settings.browser_profile deve ser um caminho de pasta (ou vazio para janela anônima).")
    if not isinstance(settings.report_company, str) or not settings.report_company.strip():
        raise ConfigError("settings.report_company deve ser o nome da empresa exibido nos relatórios.")
    if not isinstance(settings.report_logo, str):
        raise ConfigError("settings.report_logo deve ser o caminho de uma imagem (ou vazio).")
    if not isinstance(settings.report_title, str) or not settings.report_title.strip():
        raise ConfigError("settings.report_title deve ser um texto.")
    return settings


def _parse_platform(name: str, data: Any) -> PlatformConfig:
    where = f"platforms.{name}"
    if not isinstance(data, dict):
        raise ConfigError(f"'{where}' deve ser um mapeamento.")
    _reject_unknown(data, {f.name for f in fields(PlatformConfig)} - {"name"}, where)

    data = dict(data)
    data.setdefault("kind", name)
    platform = PlatformConfig(name=name, **data)

    if platform.kind not in SUPPORTED_KINDS:
        raise ConfigError(f"{where}.kind '{platform.kind}' não suportado. Opções: {', '.join(SUPPORTED_KINDS)}.")
    if platform.mfa not in MFA_METHODS:
        raise ConfigError(f"{where}.mfa '{platform.mfa}' inválido. Opções: {', '.join(MFA_METHODS)}.")
    if platform.url:
        platform.url = validate_url(platform.url, name)
    elif platform.enabled:
        raise ConfigError(f"A plataforma '{name}' está ativa, mas não tem URL cadastrada.")
    if platform.login_timeout is not None and (not isinstance(platform.login_timeout, int) or platform.login_timeout <= 0):
        raise ConfigError(f"{where}.login_timeout deve ser um inteiro positivo (segundos).")
    platform.selectors = _parse_selectors(platform.selectors, where)
    if not isinstance(platform.params, dict):
        raise ConfigError(f"{where}.params deve ser um mapeamento.")
    return platform


def _parse_selectors(data: Any, where: str) -> dict[str, list[str]]:
    if not isinstance(data, dict):
        raise ConfigError(f"{where}.selectors deve ser um mapeamento.")
    unknown = sorted(k for k in data if k not in SELECTOR_FIELDS)
    if unknown:
        raise ConfigError(f"Seletor(es) desconhecido(s) em {where}: {', '.join(unknown)}. Válidos: {', '.join(SELECTOR_FIELDS)}.")
    parsed: dict[str, list[str]] = {}
    for key, value in data.items():
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v.strip() for v in values):
            raise ConfigError(f"{where}.selectors.{key} deve ser um seletor CSS ou uma lista de seletores.")
        parsed[key] = values
    return parsed


def to_dict(config: AppConfig) -> dict[str, Any]:
    platforms: dict[str, Any] = {}
    for name, p in config.platforms.items():
        entry: dict[str, Any] = {
            "kind": p.kind,
            "enabled": p.enabled,
            "url": p.url,
            "environment": p.environment,
            "description": p.description,
            "mfa": p.mfa,
        }
        if p.login_timeout is not None:
            entry["login_timeout"] = p.login_timeout
        if p.selectors:
            entry["selectors"] = p.selectors
        if p.params:
            entry["params"] = p.params
        platforms[name] = entry
    settings = {f.name: getattr(config.settings, f.name) for f in fields(Settings)}
    data: dict[str, Any] = {"settings": settings, "platforms": platforms}
    if config.notifications:
        n = config.notifications
        data["notifications"] = {
            "when": n.when, "webhook": n.webhook, "webhook_format": n.webhook_format,
            **({"email": {f.name: getattr(n.email, f.name) for f in fields(EmailConfig)}} if n.email else {}),
        }
    if config.database:
        data["database"] = {f.name: getattr(config.database, f.name) for f in fields(DatabaseConfig)}
    if config.web:
        data["web"] = {f.name: getattr(config.web, f.name) for f in fields(WebConfig)}
    if config.schedules:
        data["schedules"] = {
            name: {f.name: getattr(s, f.name) for f in fields(ScheduleConfig) if f.name != "name"}
            for name, s in config.schedules.items()
        }
    return data


def _diff(new: Any, base: Any) -> Any:
    """Só o que difere da base (para gravar o arquivo de um ambiente)."""
    if isinstance(new, dict) and isinstance(base, dict):
        out = {}
        for key, value in new.items():
            if key not in base:
                out[key] = value
            elif value != base[key]:
                sub = _diff(value, base[key])
                if sub not in ({}, None):
                    out[key] = sub
        return out
    return new if new != base else None


def save_config(config: AppConfig, path: str | Path | None = None) -> Path:
    """Grava a configuração de forma atômica (arquivo temporário + rename).

    Em um ambiente, grava no arquivo do ambiente apenas o que difere da configuração base.
    """
    # Valida antes de gravar, para nunca persistir um estado inválido.
    parse_config(to_dict(config))
    if config.environment and path is None:
        base = to_dict(parse_config(config.base_raw or {}))
        removed = sorted(set(base["platforms"]) - set(config.platforms))
        if removed:
            raise ConfigError(
                f"Plataformas da configuração base não podem ser removidas em um ambiente ({', '.join(removed)}). "
                "Desative-as neste ambiente (platforms disable) ou remova-as da base."
            )
        new = to_dict(config)
        base["settings"] = _environment_paths(base["settings"], {}, config.environment)
        overlay = _diff(new, base) or {}
        header = f"# Ambiente \"{config.environment}\": só o que difere de {config.path.name}. Gerenciado pelo jervis.\n"
        return _atomic_yaml(config.overlay_path, header, overlay)
    target = Path(path) if path else (config.path or resolve_config_path())
    header = (
        "# Arquivo gerenciado pelo jervis (comentários não são preservados).\n"
        "# Documentação dos campos: jervis/templates/platforms.example.yaml\n"
    )
    return _atomic_yaml(target, header, to_dict(config))


def _atomic_yaml(target: Path, header: str, data: dict[str, Any]) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    text = header + yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".platforms-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target

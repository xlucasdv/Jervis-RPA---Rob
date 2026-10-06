"""Interface de linha de comando: ``jervis <comando>``."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from selenium.common.exceptions import WebDriverException

from jervis import __version__
from jervis.auth.mfa import is_valid_totp_secret, normalize_totp_secret
from jervis.auth.profiles import SUPPORTED_KINDS
from jervis import scheduling
from jervis.audit import AuditLog
from jervis.health import HEALTH_EXIT, compute_health
from jervis.notify import SMTP_SECRET, WEBHOOK_SECRET, Notifier
from jervis.check import check_platform, save_check
from jervis.collectors import COLLECTORS
from jervis.consolidation import latest_run_dir, load_run
from jervis.consolidation.consolidate import CONSOLIDATED_JSON

from jervis.config import (
    MFA_METHODS,
    REPORT_FORMATS,
    AppConfig,
    PlatformConfig,
    ScheduleConfig,
    init_config,
    resolve_environment,
    to_dict,
    is_insecure_url,
    load_config,
    save_config,
    validate_url,
)
from jervis.credentials import CredentialStore, env_prefix, service_for
from jervis.errors import ConfigError, CredentialError, JervisError
from jervis.logging_setup import FILE_ONLY, setup_logging
from jervis.security import mask_username, redact
from jervis.runner import (
    CLASSIFICATION_LABEL,
    MANIFEST,
    RUN_LOG,
    STATE_LABEL,
    STATUS_LABEL,
    Runner,
    consolidate_run,
    generate_run_reports,
    is_running,
    prune_runs,
    read_history,
    running_manifests,
)
from jervis.session import platform_session

log = logging.getLogger("jervis")

# 0 sucesso; 1 erro de uso/configuração; 2 parcial (ou atenção); 3 falha (ou crítico).
EXIT_OK, EXIT_FAILURE = 0, 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return EXIT_OK

    try:
        if args.handler is cmd_init:
            setup_logging(verbose=args.verbose)
            return cmd_init(args)
        config = load_config(args.config, env=args.env)
        setup_logging(config.settings.log_file, verbose=args.verbose)
        return args.handler(args, config)
    except JervisError as exc:
        print(f"Erro: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        print("\nOperação cancelada.", file=sys.stderr)
        return 130


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jervis", description="Coleta automatizada de dados de TI (Sophos, Acronis, Zabbix).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", help="caminho do arquivo de configuração (padrão: config/platforms.yaml ou $JERVIS_CONFIG)")
    parser.add_argument("-v", "--verbose", action="store_true", help="exibe logs detalhados no terminal")
    parser.add_argument("-e", "--env", help="ambiente (ex.: dev, hml, prod): usa config/platforms.<ambiente>.yaml sobre a base; ou $JERVIS_ENV")
    sub = parser.add_subparsers(title="comandos", metavar="<comando>")

    p = sub.add_parser("init", help="cria o arquivo de configuração a partir do modelo")
    p.add_argument("--force", action="store_true", help="sobrescreve um arquivo existente")
    p.set_defaults(handler=cmd_init)

    # --- platforms ---
    plat = sub.add_parser("platforms", help="cadastro das plataformas").add_subparsers(title="ações", metavar="<ação>", required=True)

    p = plat.add_parser("list", help="lista as plataformas configuradas")
    p.add_argument("--check", action="store_true", help="testa se cada URL responde (sem autenticar)")
    p.set_defaults(handler=cmd_platforms_list)

    p = plat.add_parser("add", help="cadastra uma nova plataforma")
    p.add_argument("name")
    p.add_argument("--kind", required=True, choices=SUPPORTED_KINDS)
    p.add_argument("--url", required=True)
    p.add_argument("--environment", default="producao")
    p.add_argument("--description", default="")
    p.add_argument("--mfa", default="none", choices=MFA_METHODS)
    p.add_argument("--enable", action="store_true", help="já cadastra ativa")
    p.set_defaults(handler=cmd_platforms_add)

    p = plat.add_parser("set-url", help="altera a URL de uma plataforma")
    p.add_argument("name")
    p.add_argument("url")
    p.set_defaults(handler=cmd_platforms_set_url)

    p = plat.add_parser("set", help="altera ambiente, descrição, MFA ou tempo limite")
    p.add_argument("name")
    p.add_argument("--environment")
    p.add_argument("--description")
    p.add_argument("--mfa", choices=MFA_METHODS)
    p.add_argument("--login-timeout", type=int, metavar="SEGUNDOS")
    p.set_defaults(handler=cmd_platforms_set)

    for action, enabled in (("enable", True), ("disable", False)):
        p = plat.add_parser(action, help=f"{'ativa' if enabled else 'desativa'} a coleta da plataforma")
        p.add_argument("names", nargs="+", metavar="name")
        p.set_defaults(handler=cmd_platforms_toggle, enabled=enabled)

    p = plat.add_parser("remove", help="remove uma plataforma do cadastro (e suas credenciais)")
    p.add_argument("name")
    p.set_defaults(handler=cmd_platforms_remove)

    # --- credentials ---
    cred = sub.add_parser("credentials", help="credenciais no cofre do sistema").add_subparsers(title="ações", metavar="<ação>", required=True)

    p = cred.add_parser("set", help="cadastra/atualiza usuário e senha (a senha é pedida de forma oculta)")
    p.add_argument("name")
    p.add_argument("--username", help="usuário (se omitido, será perguntado)")
    p.add_argument("--totp", action="store_true", help="também cadastra o segredo TOTP do MFA")
    p.set_defaults(handler=cmd_credentials_set)

    p = cred.add_parser("delete", help="remove as credenciais do cofre")
    p.add_argument("name")
    p.set_defaults(handler=cmd_credentials_delete)

    # --- login ---
    p = sub.add_parser("login", help="testa o login automatizado nas plataformas ativas")
    p.add_argument("names", nargs="*", metavar="name", help="plataformas (padrão: todas as ativas)")
    p.add_argument("--headed", action="store_true", help="exibe o navegador durante o login")
    p.set_defaults(handler=cmd_login)

    # --- status ---
    p = sub.add_parser("status", help="saúde da ferramenta: OK, atenção ou crítico (código de saída 0/2/3)")
    p.add_argument("--json", action="store_true", help="saída em JSON (para monitoramento externo, ex.: Zabbix)")
    p.set_defaults(handler=cmd_status)

    # --- notify ---
    notify = sub.add_parser("notify", help="notificações por e-mail e webhook").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = notify.add_parser("set-smtp-password", help="cadastra a senha do SMTP no cofre do sistema")
    p.set_defaults(handler=cmd_notify_set_smtp_password)
    p = notify.add_parser("set-webhook", help="cadastra a URL do webhook (Teams/Slack) no cofre do sistema")
    p.set_defaults(handler=cmd_notify_set_webhook)
    p = notify.add_parser("test", help="envia uma notificação de teste pelos canais configurados")
    p.add_argument("--status", choices=("sucesso", "parcial", "falha"), default="falha")
    p.set_defaults(handler=cmd_notify_test)

    # --- config ---
    cfg = sub.add_parser("config", help="configuração efetiva (base + ambiente)").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = cfg.add_parser("show", help="mostra a configuração efetiva, já combinada com o arquivo do ambiente")
    p.set_defaults(handler=cmd_config_show)

    # --- check ---
    p = sub.add_parser("check", help="verifica login, páginas e colunas nas plataformas reais, sem coletar dados")
    p.add_argument("names", nargs="*", metavar="name", help="plataformas (padrão: todas as ativas)")
    p.add_argument("--headed", action="store_true", help="exibe o navegador durante a verificação")
    p.add_argument("--screenshots", action="store_true", help="salva uma captura de cada página verificada")
    p.set_defaults(handler=cmd_check)

    # --- collect ---
    p = sub.add_parser("collect", help="coleta os dados das plataformas ativas")
    p.add_argument("names", nargs="*", metavar="name", help="plataformas (padrão: todas as ativas)")
    p.add_argument("--output", metavar="DIR", help="diretório base dos resultados (padrão: settings.output_dir)")
    p.add_argument("--headed", action="store_true", help="exibe o navegador durante a coleta")
    p.add_argument("--retry", type=int, default=0, metavar="N", help="reprocessa automaticamente as falhas até N vezes")
    p.add_argument("--retry-delay", type=float, default=0, metavar="MIN", help="minutos de espera antes de reprocessar")
    p.set_defaults(handler=cmd_collect)

    # --- retry ---
    p = sub.add_parser("retry", help="reprocessa as plataformas/etapas que falharam em uma execução")
    p.add_argument("run_dir", nargs="?", metavar="DIR", help="diretório da execução (padrão: a mais recente)")
    p.add_argument("--platforms", metavar="LISTA", help="só estas plataformas (separadas por vírgula)")
    p.add_argument("--headed", action="store_true", help="exibe o navegador")
    p.set_defaults(handler=cmd_retry)

    # --- runs ---
    runs = sub.add_parser("runs", help="histórico e acompanhamento das execuções")
    runs.add_argument("--limit", type=int, default=15, help="quantidade de execuções exibidas (padrão: 15)")
    runs.set_defaults(handler=cmd_runs)
    runs_sub = runs.add_subparsers(title="ações", metavar="<ação>")
    p = runs_sub.add_parser("show", help="detalhes de uma execução")
    p.add_argument("run_id", nargs="?", metavar="EXECUÇÃO", help="ex.: 20261006-070000 (padrão: a mais recente)")
    p.set_defaults(handler=cmd_runs_show)
    p = runs_sub.add_parser("prune", help="remove pastas de execução antigas (o histórico é mantido)")
    p.add_argument("--days", type=int, metavar="N", help="idade mínima em dias (padrão: settings.retention_days)")
    p.set_defaults(handler=cmd_runs_prune)

    # --- audit ---
    p = sub.add_parser("audit", help="trilha de auditoria: quem iniciou coletas e alterou a configuração")
    p.add_argument("--limit", type=int, default=30, help="quantidade de eventos (padrão: 30)")
    p.add_argument("--event", metavar="TEXTO", help="filtra por tipo de evento (ex.: coleta, credencial)")
    p.add_argument("--verify", action="store_true", help="verifica se a trilha foi alterada")
    p.set_defaults(handler=cmd_audit)

    # --- schedule ---
    sched = sub.add_parser("schedule", help="agendamento automático das coletas").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = sched.add_parser("list", help="lista os agendamentos e a próxima execução")
    p.set_defaults(handler=cmd_schedule_list)
    p = sched.add_parser("install", help="registra os agendamentos no Agendador de Tarefas do Windows")
    p.add_argument("names", nargs="*", metavar="nome", help="agendamentos (padrão: todos os ativos)")
    p.add_argument("--dry-run", action="store_true", help="só mostra os comandos, sem registrar")
    p.set_defaults(handler=cmd_schedule_install)
    p = sched.add_parser("uninstall", help="remove as tarefas do Agendador de Tarefas")
    p.add_argument("names", nargs="*", metavar="nome", help="agendamentos (padrão: todas as tarefas do Jervis3000)")
    p.set_defaults(handler=cmd_schedule_uninstall)
    p = sched.add_parser("run", help="executa um agendamento agora (é o que a tarefa agendada chama)")
    p.add_argument("name", metavar="nome")
    p.set_defaults(handler=cmd_schedule_run)
    p = sched.add_parser("serve", help="agendador interno em primeiro plano (alternativa ao Agendador do Windows)")
    p.set_defaults(handler=cmd_schedule_serve)

    # --- consolidate ---
    p = sub.add_parser("consolidate", help="padroniza e consolida os resultados de uma execução de coleta")
    p.add_argument("run_dir", nargs="?", metavar="DIR", help="diretório da execução (padrão: a mais recente)")
    p.set_defaults(handler=cmd_consolidate)

    # --- report ---
    p = sub.add_parser("report", help="gera os relatórios (HTML, Excel, CSV, PDF) de uma execução de coleta")
    p.add_argument("run_dir", nargs="?", metavar="DIR", help="diretório da execução (padrão: a mais recente)")
    p.add_argument("--formats", metavar="LISTA", help=f"formatos separados por vírgula ({','.join(REPORT_FORMATS)}); padrão: settings.report_formats")
    p.add_argument("--open", action="store_true", help="abre o relatório HTML ao terminar")
    p.set_defaults(handler=cmd_report)
    return parser


# --- comandos ------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    env = resolve_environment(args.env)
    path = init_config(args.config, force=args.force, env=env)
    if env:
        print(f"Arquivo do ambiente '{env}' criado em {path}. Inclua nele só o que muda neste ambiente.")
        print(f"Use com: jervis --env {env} <comando>   (ou defina JERVIS_ENV={env})")
        return EXIT_OK
    print(f"Configuração criada em {path}.")
    print("Próximos passos: 'jervis platforms set-url <nome> <url>', 'jervis credentials set <nome>', 'jervis platforms enable <nome>'.")
    return EXIT_OK


def cmd_platforms_list(args: argparse.Namespace, config: AppConfig) -> int:
    if not config.platforms:
        print("Nenhuma plataforma cadastrada. Use 'jervis platforms add'.")
        return EXIT_OK
    store = _store(config)
    platforms = list(config.platforms.values())
    headers = ["NOME", "TIPO", "AMBIENTE", "ATIVA", "MFA", "CREDENCIAIS", "URL"]
    rows = [
        [p.name, p.kind, p.environment, "sim" if p.enabled else "não", p.mfa, _credential_label(store, p), p.url or "(não definida)"]
        for p in platforms
    ]
    if args.check:
        headers.append("DISPONIBILIDADE")
        with ThreadPoolExecutor(max_workers=8) as pool:
            for row, status in zip(rows, pool.map(_check_url, platforms)):
                row.append(status)
    _print_table(headers, rows)
    print(f"\n{len(config.enabled_platforms())} de {len(platforms)} plataforma(s) ativa(s) para coleta. Arquivo: {config.path}")
    return EXIT_OK


def cmd_platforms_add(args: argparse.Namespace, config: AppConfig) -> int:
    if args.name in config.platforms:
        raise ConfigError(f"A plataforma '{args.name}' já existe. Use 'jervis platforms set-url' ou 'jervis platforms set'.")
    url = _checked_url(args.url, args.name)
    config.platforms[args.name] = PlatformConfig(
        name=args.name, kind=args.kind, url=url, enabled=args.enable,
        environment=args.environment, description=args.description, mfa=args.mfa,
    )
    save_config(config)
    _audit(config, "plataforma_cadastrada", plataforma=args.name, tipo=args.kind, url=url, ativa=args.enable)
    print(f"Plataforma '{args.name}' cadastrada ({'ativa' if args.enable else 'inativa'}).")
    if not _store(config).status(args.name).configured:
        print(f"Cadastre as credenciais com: jervis credentials set {args.name}")
    return EXIT_OK


def cmd_platforms_set_url(args: argparse.Namespace, config: AppConfig) -> int:
    platform = config.get(args.name)
    previous_url = platform.url
    platform.url = _checked_url(args.url, args.name)
    save_config(config)
    _audit(config, "plataforma_url_alterada", plataforma=args.name, de=previous_url, para=platform.url)
    print(f"URL de '{args.name}' atualizada para {platform.url}.")
    return EXIT_OK


def cmd_platforms_set(args: argparse.Namespace, config: AppConfig) -> int:
    platform = config.get(args.name)
    changes = {
        "environment": args.environment,
        "description": args.description,
        "mfa": args.mfa,
        "login_timeout": args.login_timeout,
    }
    changes = {k: v for k, v in changes.items() if v is not None}
    if not changes:
        raise ConfigError("Nada a alterar. Informe --environment, --description, --mfa e/ou --login-timeout.")
    for key, value in changes.items():
        setattr(platform, key, value)
    save_config(config)
    _audit(config, "plataforma_alterada", plataforma=args.name, alteracoes=changes)
    print(f"Plataforma '{args.name}' atualizada: " + ", ".join(f"{k}={v}" for k, v in changes.items()))
    return EXIT_OK


def cmd_platforms_toggle(args: argparse.Namespace, config: AppConfig) -> int:
    platforms = [config.get(name) for name in args.names]
    if args.enabled:
        missing = [p.name for p in platforms if not p.url]
        if missing:
            raise ConfigError(f"Defina a URL antes de ativar: {', '.join(missing)} (jervis platforms set-url <nome> <url>).")
    for p in platforms:
        p.enabled = args.enabled
    save_config(config)
    _audit(config, "plataforma_ativada" if args.enabled else "plataforma_desativada", plataformas=[p.name for p in platforms])
    state = "ativada(s)" if args.enabled else "desativada(s)"
    print(f"Plataforma(s) {state}: {', '.join(p.name for p in platforms)}.")
    if args.enabled:
        store = _store(config)
        for p in platforms:
            if not store.status(p.name).configured:
                print(f"Atenção: '{p.name}' ainda não tem credenciais. Use 'jervis credentials set {p.name}'.")
    return EXIT_OK


def cmd_platforms_remove(args: argparse.Namespace, config: AppConfig) -> int:
    config.get(args.name)
    del config.platforms[args.name]
    save_config(config)
    _audit(config, "plataforma_removida", plataforma=args.name)
    try:
        _store(config).delete(args.name)
    except CredentialError as exc:
        print(f"Atenção: {exc}", file=sys.stderr)
    print(f"Plataforma '{args.name}' removida.")
    return EXIT_OK


def cmd_credentials_set(args: argparse.Namespace, config: AppConfig) -> int:
    # Exige plataforma cadastrada, evitando credenciais órfãs por erro de digitação.
    platform = config.get(args.name)
    username = args.username or input(f"Usuário para {platform.name}: ").strip()
    password = getpass.getpass("Senha: ")
    if password != getpass.getpass("Confirme a senha: "):
        raise CredentialError("As senhas não conferem. Nada foi alterado.")

    totp_secret = None
    if args.totp or platform.mfa == "totp":
        totp_secret = normalize_totp_secret(getpass.getpass("Segredo TOTP (chave base32 exibida ao configurar o autenticador): "))
        if not is_valid_totp_secret(totp_secret):
            raise CredentialError("Segredo TOTP inválido (esperado texto base32, ex.: JBSWY3DPEHPK3PXP). Nada foi alterado.")

    store = _store(config)
    store.set(platform.name, username, password, totp_secret)
    _audit(config, "credencial_cadastrada", plataforma=platform.name, usuario=mask_username(username), totp=bool(totp_secret))
    print(f"Credenciais de '{platform.name}' salvas no cofre do sistema ({store.backend_name()}).")
    if store.status(platform.name).source == "env":
        print(f"Atenção: as variáveis {env_prefix(platform.name)}* estão definidas e têm prioridade sobre o cofre.")
    return EXIT_OK


def cmd_credentials_delete(args: argparse.Namespace, config: AppConfig) -> int:
    if _store(config).delete(args.name):
        _audit(config, "credencial_removida", plataforma=args.name)
        print(f"Credenciais de '{args.name}' removidas do cofre.")
    else:
        print(f"Não havia credenciais de '{args.name}' no cofre.")
    return EXIT_OK


def cmd_login(args: argparse.Namespace, config: AppConfig) -> int:
    platforms = [config.get(n) for n in args.names] if args.names else config.enabled_platforms()
    if not platforms:
        print("Nenhuma plataforma ativa. Use 'jervis platforms enable <nome>'.")
        return EXIT_FAILURE

    settings = config.settings
    if args.headed:
        settings.headless = False
    store = _store(config)
    failures = 0
    for platform in platforms:
        print(f"{platform.name}: autenticando em {platform.url} ...", flush=True)
        try:
            with platform_session(platform, settings, store) as (_driver, result):
                detail = "sessão reaproveitada" if result.reused_session else ("com MFA" if result.used_mfa else "sem MFA")
                print(f"  [OK] login realizado em {result.elapsed:.1f}s ({detail})")
        except JervisError as exc:
            failures += 1
            log.error("%s", exc, extra=FILE_ONLY)
            print(f"  [FALHA] {redact(str(exc))}")
        except WebDriverException as exc:
            failures += 1
            log.exception("[%s] Erro inesperado do navegador", platform.name, extra=FILE_ONLY)
            print(f"  [FALHA] [{platform.name}] Erro inesperado do navegador: {redact((exc.msg or str(exc)).strip())}")

    print(f"\n{len(platforms) - failures} de {len(platforms)} plataforma(s) autenticada(s).")
    return EXIT_OK if failures == 0 else EXIT_FAILURE


def cmd_check(args: argparse.Namespace, config: AppConfig) -> int:
    platforms = _platforms_from(args.names, config)
    if not platforms:
        print("Nenhuma plataforma ativa. Use 'jervis platforms enable <nome>' ou informe o nome.")
        return EXIT_FAILURE
    settings = config.settings
    if args.headed:
        settings.headless = False
    directory = Path(settings.log_file).parent / "verificacao"
    screenshots = directory / "capturas" if args.screenshots else None
    store = _store(config)
    failed = False
    for platform in platforms:
        if platform.kind not in COLLECTORS:
            print(f"{platform.name}: verificação não disponível para o tipo '{platform.kind}'.")
            continue
        print(f"\n{platform.name} — {platform.url}")
        report = check_platform(platform, settings, store, progress=lambda m: print(f"  {m}"), screenshot_dir=screenshots)
        for page in report["paginas"]:
            if page["resultado"] != "ok" and page.get("colunas_na_pagina") is not None:
                print(f"    colunas na tela em {page['etapa']}: {', '.join(page['colunas_na_pagina']) or 'nenhuma'}")
        path = save_check(report, directory)
        print(f"  Resultado: {report['resultado'].upper()} — detalhes em {path}")
        failed = failed or report["resultado"] == "falha"
    if failed:
        print("\nAjuste endereços e rótulos em 'params' e seletores de login em 'selectors' (veja docs/solucao-de-problemas.md).")
    return EXIT_FAILURE if failed else EXIT_OK


def _platforms_from(names: list[str], config: AppConfig) -> list[PlatformConfig]:
    return [config.get(n) for n in names] if names else config.enabled_platforms()


def cmd_collect(args: argparse.Namespace, config: AppConfig) -> int:
    platforms = _platforms_from(args.names, config)
    if not platforms:
        print("Nenhuma plataforma ativa. Use 'jervis platforms enable <nome>'.")
        return EXIT_FAILURE
    if args.headed:
        config.settings.headless = False
    if args.output:
        config.settings.output_dir = args.output
    summary = Runner(config).run(platforms, origin="manual", retries=args.retry, retry_delay=args.retry_delay * 60)
    return summary.exit_code


def cmd_retry(args: argparse.Namespace, config: AppConfig) -> int:
    run_dir = Path(args.run_dir) if args.run_dir else latest_run_dir(config.settings.output_dir)
    names = [n.strip() for n in args.platforms.split(",") if n.strip()] if args.platforms else None
    if args.headed:
        config.settings.headless = False
    return Runner(config).retry(run_dir, names).exit_code


def cmd_consolidate(args: argparse.Namespace, config: AppConfig) -> int:
    run_dir = Path(args.run_dir) if args.run_dir else latest_run_dir(config.settings.output_dir)
    print(f"Consolidando {run_dir} ...")
    consolidate_run(load_run(run_dir), run_dir, config.settings, print)
    return EXIT_OK


def cmd_report(args: argparse.Namespace, config: AppConfig) -> int:
    settings = config.settings
    run_dir = Path(args.run_dir) if args.run_dir else latest_run_dir(settings.output_dir)
    formats = settings.report_formats
    if args.formats:
        formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
        unknown = [f for f in formats if f not in REPORT_FORMATS]
        if unknown:
            raise ConfigError(f"Formato(s) desconhecido(s): {', '.join(unknown)}. Opções: {', '.join(REPORT_FORMATS)}.")
    consolidated_path = run_dir / CONSOLIDATED_JSON
    if consolidated_path.exists():
        report = json.loads(consolidated_path.read_text(encoding="utf-8"))
    else:
        print(f"Consolidando {run_dir} ...")
        report = consolidate_run(load_run(run_dir), run_dir, settings, print)
    output = generate_run_reports(report, run_dir, settings, formats, print)
    print(f"  Pasta: {run_dir.resolve()}")
    if output and args.open and output.files.get("html"):
        _open_file(output.files["html"][0])
    return EXIT_OK if not output or not output.errors else EXIT_FAILURE


def _open_file(path: Path) -> None:
    if hasattr(os, "startfile"):
        os.startfile(path)  # Windows: abre no navegador padrão
    else:
        import webbrowser

        webbrowser.open(path.resolve().as_uri())


# --- acompanhamento (7.3) ---------------------------------------------------------


def _platforms_label(manifest: dict) -> str:
    parts = []
    for name, info in (manifest.get("plataformas") or {}).items():
        label = STATUS_LABEL.get(info.get("status")) or STATE_LABEL.get(info.get("estado"), "?")
        attempts = info.get("tentativas") or 1
        parts.append(f"{name}:{label}" + (f"({attempts} tent.)" if attempts > 1 else ""))
    return " ".join(parts)


def _when(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m %H:%M")
    except ValueError:
        return iso


def cmd_runs(args: argparse.Namespace, config: AppConfig) -> int:
    output_dir = Path(config.settings.output_dir)
    running = running_manifests(output_dir)
    active = is_running(output_dir) if running else False
    history = read_history(output_dir, args.limit)
    if not history and not running:
        print("Nenhuma execução registrada. Use 'jervis collect'.")
        return EXIT_OK
    rows = []
    for m in running:
        state = "EM ANDAMENTO" if active else "INTERROMPIDA"
        rows.append([m["id"], m.get("origem", ""), m.get("usuario", "—"), _when(m.get("inicio")), "—", state, _platforms_label(m)])
    for m in reversed(history):
        duration = f"{m['duracao_s']:.0f}s" if m.get("duracao_s") is not None else "—"
        status = "ERRO" if m.get("estado") == "erro" else STATUS_LABEL.get(m.get("status"), "?")
        warnings = sum(len(p.get("avisos") or []) for p in (m.get("plataformas") or {}).values())
        if warnings:
            status += f" ({warnings} aviso(s))"
        if m.get("falhas_relatorio") or m.get("falhas_pos_coleta"):
            status += " (relatório falhou)"
        rows.append([m["id"], m.get("origem", ""), m.get("usuario", "—"), _when(m.get("inicio")), duration,
                     status, _platforms_label(m)])
    _print_table(["EXECUÇÃO", "ORIGEM", "USUÁRIO", "INÍCIO", "DURAÇÃO", "STATUS", "PLATAFORMAS"], rows)
    if running and not active:
        print("\nExecuções INTERROMPIDAS não terminaram (processo encerrado). Reprocesse com 'jervis retry <pasta>'.")
    print("\nDetalhes: jervis runs show <execução>")
    return EXIT_OK


def cmd_runs_show(args: argparse.Namespace, config: AppConfig) -> int:
    output_dir = Path(config.settings.output_dir)
    run_dir = output_dir / args.run_id if args.run_id else latest_run_dir(output_dir)
    path = run_dir / MANIFEST
    if path.exists():
        m = json.loads(path.read_text(encoding="utf-8"))
    else:
        entries = [e for e in read_history(output_dir) if e.get("id") == run_dir.name]
        if not entries:
            raise ConfigError(f"Execução sem acompanhamento registrado: {run_dir} (anterior ao agendamento?).")
        m = entries[0]
        print("(pasta da execução já removida pela retenção; dados do histórico)")
    state = m.get("estado")
    if state == "em_andamento" and not is_running(output_dir):
        state = "interrompida"
    print(f"Execução {m['id']} ({m.get('origem')}) — {STATE_LABEL.get(state, state)}, status: {STATUS_LABEL.get(m.get('status'), '—')}")
    print(f"  Iniciada por: {m.get('usuario', '—')} em {m.get('maquina', '—')}")
    print(f"  Início: {_when(m.get('inicio'))}   Fim: {_when(m.get('fim'))}   Duração: {m.get('duracao_s') or '—'}s")
    if m.get("erro"):
        print(f"  ERRO: {m['erro']}")
    for name, info in m.get("plataformas", {}).items():
        counts = " | ".join(f"{k}: {v}" for k, v in (info.get("contagens") or {}).items())
        status = STATUS_LABEL.get(info.get("status")) or STATE_LABEL.get(info.get("estado"), "?")
        print(f"  {name}: [{status}] tentativas: {info.get('tentativas', 1)}  {counts}")
        for failure in info.get("falhas") or []:
            print(f"      erro: {failure}")
        for warning in info.get("avisos") or []:
            print(f"      aviso: {warning}")
    if m.get("consolidado"):
        print("  Consolidado: " + " | ".join(f"{CLASSIFICATION_LABEL.get(k, k)}: {v}" for k, v in m["consolidado"].items()))
    for retry in m.get("reprocessamentos", []):
        took = f" ({retry['duracao_s']:.0f}s)" if retry.get("duracao_s") is not None else ""
        print(f"  Reprocessado em {_when(retry['em'])}{took}: {', '.join(retry['plataformas']) or 'nada a reprocessar'}")
    if m.get("relatorios"):
        print(f"  Relatórios: {', '.join(m['relatorios'])}")
    for fmt, error in (m.get("falhas_relatorio") or {}).items():
        print(f"  Relatório {fmt.upper()} não gerado: {error}")
    if m.get("falhas_pos_coleta"):
        print(f"  Consolidação/relatórios falharam: {m['falhas_pos_coleta']}")
    print(f"  Pasta: {run_dir.resolve()}  (progresso completo em {RUN_LOG})")
    return EXIT_OK


def cmd_runs_prune(args: argparse.Namespace, config: AppConfig) -> int:
    days = config.settings.retention_days if args.days is None else args.days
    if days <= 0:
        print("Retenção desativada (retention_days: 0). Informe --days N para remover pastas antigas.")
        return EXIT_OK
    removed = prune_runs(Path(config.settings.output_dir), days)
    if removed:
        _audit(config, "retencao_aplicada", pastas_removidas=removed, dias=days)
    print(f"{len(removed)} pasta(s) de execução com mais de {days} dias removida(s)." + (f" ({', '.join(removed)})" if removed else ""))
    print("O histórico (jervis runs) e a trilha de auditoria são mantidos.")
    return EXIT_OK


# --- auditoria (8.4) -----------------------------------------------------------------


def _audit(config: AppConfig, event: str, **details) -> None:
    try:
        AuditLog(config.settings.audit_file, config.environment).record(event, **details)
    except OSError as exc:  # a ação já foi feita; avisa, mas não desfaz
        print(f"Atenção: não foi possível registrar a auditoria ({exc}).", file=sys.stderr)


def cmd_audit(args: argparse.Namespace, config: AppConfig) -> int:
    trail = AuditLog(config.settings.audit_file, config.environment)
    if args.verify:
        ok, message = trail.verify()
        print(("[OK] " if ok else "[ALTERADA] ") + message)
        return EXIT_OK if ok else EXIT_FAILURE
    entries = trail.read(args.limit)
    if args.event:
        entries = [e for e in entries if args.event in e["evento"]]
    if not entries:
        print(f"Nenhum evento de auditoria em {trail.path}.")
        return EXIT_OK
    rows = []
    for e in entries:
        details = ", ".join(f"{k}={_short(v)}" for k, v in e.get("detalhes", {}).items() if v not in (None, [], {}))
        rows.append([_when(e["em"]), e["evento"], e["usuario"], e["maquina"], details])
    _print_table(["QUANDO", "EVENTO", "USUÁRIO", "MÁQUINA", "DETALHES"], rows)
    print(f"\nArquivo: {trail.path}  (verifique a integridade com 'jervis audit --verify')")
    return EXIT_OK


def _short(value) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= 70 else text[:67] + "..."


# --- agendamento (7.2) ---------------------------------------------------------------


def cmd_schedule_list(args: argparse.Namespace, config: AppConfig) -> int:
    if not config.schedules:
        print("Nenhum agendamento configurado. Inclua a seção 'schedules' no arquivo de configuração.")
        return EXIT_OK
    try:
        installed = scheduling.installed_tasks(env=config.environment)
    except scheduling.SchedulerError:
        installed = None
    now = datetime.now()
    rows = []
    for s in config.schedules.values():
        tasks = scheduling.task_names(s, config.environment)
        in_windows = "?" if installed is None else ("sim" if all(t in installed for t in tasks) else "não")
        rows.append([
            s.name, "sim" if s.enabled else "não", scheduling.describe(s), ", ".join(s.platforms) or "todas as ativas",
            f"{scheduling.next_run(s, now):%d/%m %H:%M}" if s.enabled else "—", in_windows,
        ])
    _print_table(["NOME", "ATIVO", "QUANDO", "PLATAFORMAS", "PRÓXIMA", "NO WINDOWS"], rows)
    if installed is not None and any(r[1] == "sim" and r[5] == "não" for r in rows):
        print("\nHá agendamentos ativos não registrados no Agendador de Tarefas: execute 'jervis schedule install'.")
    return EXIT_OK


def cmd_schedule_install(args: argparse.Namespace, config: AppConfig) -> int:
    commands = scheduling.install(config, args.names or None, dry_run=args.dry_run)
    if not args.dry_run:
        _audit(config, "agendamento_instalado", agendamentos=args.names or [s.name for s in config.schedules.values() if s.enabled],
               tarefas=len(commands))
    verb = "Seriam executados" if args.dry_run else "Tarefas registradas no Agendador de Tarefas do Windows"
    print(f"{verb}:")
    for command in commands:
        print(f"  {command}")
    if not args.dry_run:
        print("\nAs tarefas rodam com o seu usuário do Windows (que tem acesso às credenciais cadastradas),")
        print("enquanto você estiver conectado. Para rodar com a sessão desconectada, abra o Agendador de")
        print("Tarefas > pasta Jervis3000 > Propriedades > 'Executar estando o usuário conectado ou não'.")
    return EXIT_OK


def cmd_schedule_uninstall(args: argparse.Namespace, config: AppConfig) -> int:
    removed = scheduling.uninstall(args.names or None, env=config.environment)
    if removed:
        _audit(config, "agendamento_removido", tarefas=removed)
    print("Tarefas removidas: " + (", ".join(removed) if removed else "nenhuma encontrada."))
    return EXIT_OK


def _run_schedule(config: AppConfig, schedule: ScheduleConfig) -> int:
    if not schedule.enabled:
        print(f"Agendamento '{schedule.name}' está desativado; nada a fazer.")
        return EXIT_OK
    platforms = _platforms_from(schedule.platforms, config)
    if not platforms:
        print("Nenhuma plataforma ativa para coletar.")
        return EXIT_FAILURE
    config.settings.headless = True  # execução sem ninguém olhando
    summary = Runner(config).run(
        platforms, origin=f"agendamento:{schedule.name}",
        retries=schedule.retries, retry_delay=schedule.retry_delay_minutes * 60,
    )
    return summary.exit_code


def cmd_schedule_run(args: argparse.Namespace, config: AppConfig) -> int:
    if args.name not in config.schedules:
        raise ConfigError(f"Agendamento '{args.name}' não cadastrado. Cadastrados: {', '.join(config.schedules) or 'nenhum'}.")
    return _run_schedule(config, config.schedules[args.name])


def cmd_schedule_serve(args: argparse.Namespace, config: AppConfig) -> int:
    def run(schedule: ScheduleConfig) -> None:
        try:  # uma execução com problema não deve derrubar o agendador
            _run_schedule(load_config(args.config, env=args.env), schedule)
        except JervisError as exc:
            print(f"Erro: {redact(str(exc))}", file=sys.stderr)

    scheduling.serve(lambda: load_config(args.config, env=args.env), run)
    return EXIT_OK


_HEALTH_LABEL = {"ok": "OK", "atencao": "ATENÇÃO", "critico": "CRÍTICO"}


def cmd_status(args: argparse.Namespace, config: AppConfig) -> int:
    status = compute_health(config)
    if args.json:
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return HEALTH_EXIT[status["saude"]]
    env = f" (ambiente {config.environment})" if config.environment else ""
    print(f"Saúde da ferramenta{env}: {_HEALTH_LABEL[status['saude']]}" + (" — coleta em andamento" if status["em_execucao"] else ""))
    for reason in status["motivos"]:
        print(f"  - {reason}")
    last = status["ultima_execucao"]
    if last:
        print(f"Última execução: {last['id']} ({last['origem']}) — {STATUS_LABEL.get(last.get('status'), last.get('estado'))}")
    rows = [
        [name, STATUS_LABEL.get(info["ultimo_status"], "—"), _when(info["ultima_coleta"]), _when(info["ultimo_sucesso"]),
         "—" if info.get("horas_sem_sucesso") is None else f"{info['horas_sem_sucesso']:g} h"]
        for name, info in status["plataformas"].items()
    ]
    if rows:
        print()
        _print_table(["PLATAFORMA", "ÚLTIMO STATUS", "ÚLTIMA COLETA", "ÚLTIMO SUCESSO", "SEM SUCESSO HÁ"], rows)
    return HEALTH_EXIT[status["saude"]]


def cmd_notify_set_smtp_password(args: argparse.Namespace, config: AppConfig) -> int:
    password = getpass.getpass("Senha do SMTP: ")
    if not password or password != getpass.getpass("Confirme a senha: "):
        raise CredentialError("Senha vazia ou não confere. Nada foi alterado.")
    _store(config).set_secret(SMTP_SECRET, password)
    _audit(config, "notificacao_smtp_senha_cadastrada")
    print("Senha do SMTP salva no cofre do sistema.")
    return EXIT_OK


def cmd_notify_set_webhook(args: argparse.Namespace, config: AppConfig) -> int:
    url = getpass.getpass("URL do webhook (não será exibida): ").strip()
    if not url.startswith("https://"):
        raise ConfigError("A URL do webhook deve começar com https://. Nada foi alterado.")
    _store(config).set_secret(WEBHOOK_SECRET, url)
    _audit(config, "notificacao_webhook_cadastrado")
    print("URL do webhook salva no cofre do sistema.")
    return EXIT_OK


def cmd_notify_test(args: argparse.Namespace, config: AppConfig) -> int:
    if not config.notifications:
        raise ConfigError("Nenhuma notificação configurada. Inclua a seção 'notifications' no arquivo de configuração.")
    manifest = {
        "id": "teste", "origem": "teste de notificação", "ambiente": config.environment, "estado": "concluida",
        "status": args.status, "plataformas": {"exemplo": {"status": args.status, "contagens": {"registros": 0}}},
    }
    errors = Notifier(config.notifications, _store(config)).notify(manifest, Path(config.settings.output_dir), force=True)
    channels = [c for c, on in (("email", config.notifications.email), ("webhook", config.notifications.webhook)) if on]
    for channel in channels:
        print(f"  {channel}: " + (f"FALHOU — {errors[channel]}" if channel in errors else "enviado"))
    return EXIT_FAILURE if errors else EXIT_OK


def cmd_config_show(args: argparse.Namespace, config: AppConfig) -> int:
    import yaml

    sources = f"{config.path}" + (f" + {config.overlay_path}" if config.overlay_path else "")
    print(f"# Ambiente: {config.environment or 'base'}   Arquivos: {sources}")
    print(f"# Cofre de credenciais: {service_for(config.environment)}")
    print(yaml.safe_dump(to_dict(config), allow_unicode=True, sort_keys=False).rstrip())
    return EXIT_OK


def _store(config: AppConfig) -> CredentialStore:
    """Cofre de credenciais do ambiente ativo."""
    return CredentialStore(service_for(config.environment))


# --- auxiliares ----------------------------------------------------------------


def _checked_url(url: str, name: str) -> str:
    url = validate_url(url, name)
    if is_insecure_url(url):
        print(f"Atenção: a URL de '{name}' usa HTTP sem criptografia; as credenciais trafegarão em texto aberto.", file=sys.stderr)
    return url


def _credential_label(store: CredentialStore, platform: PlatformConfig) -> str:
    try:
        status = store.status(platform.name)
    except CredentialError:
        return "erro no cofre"
    if not status.configured:
        return "ausente"
    label = {"env": "variáveis amb.", "keyring": "cofre"}[status.source]
    if platform.mfa == "totp":
        label += " +TOTP" if status.has_totp else " (sem TOTP!)"
    return label


def _check_url(platform: PlatformConfig) -> str:
    if not platform.url:
        return "-"
    request = urllib.request.Request(platform.url, method="GET", headers={"User-Agent": f"jervis/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return f"online (HTTP {response.status})"
    except urllib.error.HTTPError as exc:
        # Qualquer resposta HTTP (inclusive 401/403) significa que o servidor está no ar.
        return f"online (HTTP {exc.code})"
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return "certificado inválido"
        return f"inacessível ({reason})"
    except (TimeoutError, OSError) as exc:
        return f"inacessível ({type(exc).__name__})"


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows)]
    for line in (headers, *rows):
        print("  ".join(str(c).ljust(w) for c, w in zip(line, widths)).rstrip())

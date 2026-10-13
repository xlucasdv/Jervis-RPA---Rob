"""Interface de linha de comando: ``jervis <comando>``."""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from selenium.common.exceptions import WebDriverException

from jervis import __version__
from jervis.auth.mfa import is_valid_totp_secret, normalize_totp_secret
from jervis.auth.profiles import SUPPORTED_KINDS
from jervis import db, driver, scheduling
from jervis.db import crypto, repository
from jervis.api import ApiError, credentials as api_credentials
from jervis.audit import AuditLog, actor
from jervis.health import HEALTH_EXIT, compute_health
from jervis.notify import SMTP_SECRET, WEBHOOK_SECRET, Notifier
from jervis.check import check_platform, save_check
from jervis.collectors import COLLECTORS
from jervis.consolidation import latest_run_dir, load_run
from jervis.consolidation.consolidate import CONSOLIDATED_JSON

from jervis.config import (
    FORBIDDEN_KEYS,
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
    # Saída redirecionada para arquivo (agendamentos) usa a página de código do Windows: um caractere
    # fora dela não pode derrubar a execução.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
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
        if config.database and args.handler not in _DB_SETUP_COMMANDS:
            _ensure_tables(config)
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
    ia = sub.add_parser("ia", help="redação do relatório executivo pela IA (Claude)").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = ia.add_parser("set-key", help="cadastra a chave da API do Claude no cofre do sistema")
    p.set_defaults(handler=cmd_ia_set_key)
    p = ia.add_parser("delete-key", help="remove a chave da API do Claude do cofre")
    p.set_defaults(handler=cmd_ia_delete_key)

    notify = sub.add_parser("notify", help="notificações por e-mail e webhook").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = notify.add_parser("set-smtp-password", help="cadastra a senha do SMTP no cofre do sistema")
    p.set_defaults(handler=cmd_notify_set_smtp_password)
    p = notify.add_parser("set-webhook", help="cadastra a URL do webhook (Teams/Slack) no cofre do sistema")
    p.set_defaults(handler=cmd_notify_set_webhook)
    p = notify.add_parser("test", help="envia uma notificação de teste pelos canais configurados")
    p.add_argument("--status", choices=("sucesso", "parcial", "falha"),
                   help="em vez da mensagem de teste, mostra como chega o aviso de uma coleta com esta situação")
    p.set_defaults(handler=cmd_notify_test)

    # --- config ---
    cfg = sub.add_parser("config", help="configuração efetiva (base + ambiente)").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = cfg.add_parser("show", help="mostra a configuração efetiva, já combinada com o arquivo do ambiente")
    p.set_defaults(handler=cmd_config_show)

    # --- db ---
    dbp = sub.add_parser("db", help="banco de dados (MySQL): tabelas, credenciais e chave de criptografia").add_subparsers(
        title="ações", metavar="<ação>", required=True)
    p = dbp.add_parser("init", help="cria o banco e as tabelas que ainda não existem")
    p.set_defaults(handler=cmd_db_init)
    p = dbp.add_parser("status", help="testa a conexão e mostra as tabelas e a quantidade de linhas")
    p.set_defaults(handler=cmd_db_status)
    p = dbp.add_parser("set-credentials", help="cadastra usuário e senha do MySQL no cofre (a senha é pedida de forma oculta)")
    p.add_argument("--username", help="usuário do MySQL (se omitido, será perguntado)")
    p.set_defaults(handler=cmd_db_set_credentials)
    p = dbp.add_parser("generate-key", help="gera a chave que criptografa as chaves MFA guardadas no banco (fica no cofre)")
    p.add_argument("--force", action="store_true", help="substitui a chave existente (as chaves MFA já gravadas ficam ilegíveis)")
    p.set_defaults(handler=cmd_db_generate_key)

    # --- customers / services (cadastro no banco) ---
    cust = sub.add_parser("customers", help="clientes no banco e os serviços de cada um").add_subparsers(
        title="ações", metavar="<ação>", required=True)
    p = cust.add_parser("add", help="cadastra um cliente")
    p.add_argument("name", help="nome do cliente")
    p.add_argument("--desk-manager-id", help="id do cliente no Desk Manager")
    p.set_defaults(handler=cmd_customers_add)
    p = cust.add_parser("list", help="lista os clientes e os serviços vinculados")
    p.set_defaults(handler=cmd_customers_list)
    p = cust.add_parser("show", help="detalhes de um cliente")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.set_defaults(handler=cmd_customers_show)
    p = cust.add_parser("update", help="altera nome ou id do Desk Manager")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.add_argument("--name", help="novo nome")
    p.add_argument("--desk-manager-id", help="novo id do Desk Manager (vazio \"\" remove)")
    p.set_defaults(handler=cmd_customers_update)
    p = cust.add_parser("remove", help="remove o cliente e os vínculos dele (inclusive as chaves MFA)")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.add_argument("--yes", action="store_true", help="não pede confirmação")
    p.set_defaults(handler=cmd_customers_remove)
    p = cust.add_parser("deactivate", help="inativa o cliente (POC, trial, cadastro antigo): fica fora do fechamento mensal e do --all")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.add_argument("--reason", help="motivo (ex.: POC encerrada)")
    p.set_defaults(handler=cmd_customers_deactivate)
    p = cust.add_parser("activate", help="reativa o cliente")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.set_defaults(handler=cmd_customers_activate)
    p = cust.add_parser("merge", help="junta dois cadastros do mesmo cliente: vínculos e histórico da origem vão para o destino")
    p.add_argument("source", metavar="origem", help="cadastro que deixa de existir (id, id do Desk Manager ou nome)")
    p.add_argument("target", metavar="destino", help="cadastro que fica")
    p.add_argument("--yes", action="store_true", help="não pede confirmação")
    p.set_defaults(handler=cmd_customers_merge)
    p = cust.add_parser("duplicates", help="sugere cadastros duplicados e de teste (POC, trial) para revisar; não altera nada")
    p.set_defaults(handler=cmd_customers_duplicates)
    p = cust.add_parser("link", help="vincula o cliente a um serviço (ou atualiza o vínculo)")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.add_argument("service", help="slug do serviço (ex.: acronis)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--mfa", action="store_true", help="pede a chave MFA (segredo TOTP) de forma oculta e grava criptografada")
    group.add_argument("--clear-mfa", action="store_true", help="apaga a chave MFA do vínculo")
    p.add_argument("--external-name", help="nome ou identificador do cliente na plataforma (vazio \"\" = usa o nome do cadastro)")
    p.add_argument("--products", help="produtos contratados, separados por ';' (vazio \"\" apaga)")
    p.add_argument("--contracted", type=int, help="quantidade de dispositivos contratados (0 apaga)")
    p.set_defaults(handler=cmd_customers_link)
    p = cust.add_parser("report", help="relatório geral do cliente coletado por API (Acronis, Sophos Central e Zabbix)")
    p.add_argument("customer", nargs="?", help="id, id do Desk Manager ou nome")
    p.add_argument("--all", dest="all_customers", action="store_true",
                   help="todos os clientes vinculados a Acronis, Sophos ou Zabbix, um após o outro")
    period = p.add_mutually_exclusive_group()
    period.add_argument("--month", help="mês AAAA-MM (padrão: o mês atual, até hoje)")
    period.add_argument("--days", type=int, help="em vez do mês: últimos N dias")
    p.add_argument("--notes", help="arquivo YAML com destaques, notas e recomendações da equipe "
                                   "(padrão: notas/<cliente>/<AAAA-MM>.yaml, se existir)")
    p.add_argument("--formats", help="formatos separados por vírgula (html,xlsx,csv,pdf); padrão: settings.report_formats")
    p.add_argument("--open", action="store_true", help="abre o relatório HTML ao terminar")
    p.add_argument("--ia", action="store_true", help="texto do relatório executivo redigido pela IA (Claude); "
                                                     "números conferidos com os dados, senão usa o texto padrão")
    p.set_defaults(handler=cmd_customers_report)
    p = cust.add_parser("unlink", help="desvincula o cliente de um serviço (apaga a chave MFA do vínculo)")
    p.add_argument("customer", help="id, id do Desk Manager ou nome")
    p.add_argument("service", help="slug do serviço")
    p.set_defaults(handler=cmd_customers_unlink)

    rev = sub.add_parser("reviews", help="revisão dos relatórios por cliente antes do envio").add_subparsers(
        title="ações", metavar="<ação>", required=True)
    p = rev.add_parser("list", help="relatórios gerados e a situação da revisão")
    p.add_argument("--status", default="pendente", choices=(*repository.REVIEW_STATUSES, "todos"),
                   help="padrão: pendente")
    p.add_argument("--month", help="competência AAAA-MM")
    p.set_defaults(handler=cmd_reviews_list)
    for action, helptext, handler in (("approve", "aprova o relatório (registra quem e quando) e mostra os arquivos para enviar", cmd_reviews_approve),
                                      ("reject", "rejeita o relatório, com o motivo", cmd_reviews_reject),
                                      ("open", "abre o relatório executivo (ou a pasta) para revisar", cmd_reviews_open)):
        p = rev.add_parser(action, help=helptext)
        p.add_argument("report", metavar="cliente|#id", help="cliente (o pendente mais recente) ou #id da revisão")
        p.add_argument("--month", help="competência AAAA-MM (quando o cliente tem mais de um pendente)")
        if action == "approve":
            p.add_argument("--note", help="observação da aprovação")
        if action == "reject":
            p.add_argument("--reason", required=True, help="motivo da rejeição")
        p.set_defaults(handler=handler)
    p = sub.add_parser("month-close", help="fechamento mensal: relatórios de todos os clientes do mês anterior, "
                                           "pendentes de revisão, e aviso à equipe")
    p.add_argument("--month", help="competência AAAA-MM (padrão: o mês anterior)")
    p.add_argument("--no-notify", action="store_true", help="não avisa a equipe (Teams/e-mail)")
    p.set_defaults(handler=cmd_month_close)

    svc = sub.add_parser("services", help="serviços (plataformas) no banco e suas configurações").add_subparsers(
        title="ações", metavar="<ação>", required=True)
    p = svc.add_parser("add", help="cadastra um serviço")
    p.add_argument("slug", help="identificador curto (ex.: acronis)")
    p.add_argument("--url", required=True, help="endereço da plataforma")
    p.add_argument("--class", dest="class_identifier", required=True,
                   help=f"coletor: {', '.join(sorted(COLLECTORS))} ou caminho Python (pacote.modulo.Classe)")
    p.add_argument("--set", action="append", default=[], metavar="CHAVE=VALOR", help="configuração extra (repetível), ex.: mfa=totp")
    p.set_defaults(handler=cmd_services_add)
    p = svc.add_parser("list", help="lista os serviços")
    p.set_defaults(handler=cmd_services_list)
    p = svc.add_parser("update", help="altera url, classe ou configurações")
    p.add_argument("slug")
    p.add_argument("--url")
    p.add_argument("--class", dest="class_identifier")
    p.add_argument("--set", action="append", default=[], metavar="CHAVE=VALOR", help="inclui/altera uma configuração (repetível)")
    p.add_argument("--unset", action="append", default=[], metavar="CHAVE", help="remove uma configuração (repetível)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--mfa", action="store_true", help="pede a chave MFA da conta de parceiro (oculta) e grava criptografada")
    group.add_argument("--clear-mfa", action="store_true", help="apaga a chave MFA da conta de parceiro")
    p.set_defaults(handler=cmd_services_update)
    p = svc.add_parser("set-api-credentials", help="credenciais de API do serviço no cofre (Acronis e Sophos: client id/secret; "
                                                    "Zabbix: token; Desk Manager: chaves do Operador e do Ambiente)")
    p.add_argument("slug")
    p.set_defaults(handler=cmd_services_set_api_credentials)
    p = svc.add_parser("test-api", help="testa o acesso por API do serviço (só leitura)")
    p.add_argument("slug")
    p.set_defaults(handler=cmd_services_test_api)
    p = svc.add_parser("clients", help="clientes que existem na plataforma (Acronis: clientes; Zabbix: grupos de hosts) "
                                        "e a situação de cada um no cadastro")
    p.add_argument("slug")
    p.add_argument("--import", dest="do_import", action="store_true",
                   help="cadastra os que faltam e cria o vínculo com o serviço")
    p.add_argument("--only", action="append", default=[], metavar="NOME",
                   help="só estes clientes da plataforma (repetível)")
    p.add_argument("--yes", action="store_true", help="não pede confirmação ao importar")
    p.set_defaults(handler=cmd_services_clients)
    p = svc.add_parser("set-credentials", help="usuário e senha da conta de parceiro no cofre do sistema (senha oculta)")
    p.add_argument("slug")
    p.add_argument("--username", help="usuário (se omitido, será perguntado)")
    p.set_defaults(handler=cmd_services_set_credentials)
    p = svc.add_parser("remove", help="remove um serviço sem clientes vinculados")
    p.add_argument("slug")
    p.set_defaults(handler=cmd_services_remove)

    # --- driver ---
    drv = sub.add_parser("driver", help="driver do navegador (Edge): versão e atualização").add_subparsers(title="ações", metavar="<ação>", required=True)
    p = drv.add_parser("status", help="compara a versão do Edge instalado com a do driver (código de saída 0/2)")
    p.set_defaults(handler=cmd_driver_status)
    p = drv.add_parser("update", help="baixa da Microsoft o driver da versão do Edge instalado, se necessário")
    p.add_argument("--force", action="store_true", help="baixa de novo mesmo se a versão já estiver correta")
    p.add_argument("--auto", action=argparse.BooleanOptionalAction, default=None,
                   help="ativa (--auto) ou desativa (--no-auto) a atualização antes de cada coleta")
    p.set_defaults(handler=cmd_driver_update)

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
    _prepare_driver(config)
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
    _prepare_driver(config)
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
            s.name, "sim" if s.enabled else "não", scheduling.describe(s),
            "fechamento mensal (relatórios por cliente)" if s.task == "relatorios_clientes" else ", ".join(s.platforms) or "todas as ativas",
            f"{scheduling.next_run(s, now):%d/%m %H:%M}" if s.enabled else "—", in_windows,
        ])
    _print_table(["NOME", "ATIVO", "QUANDO", "O QUÊ", "PRÓXIMA", "NO WINDOWS"], rows)
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
    if schedule.task == "relatorios_clientes":  # fechamento mensal dos relatórios por cliente
        from jervis.api import closing

        today = datetime.now().date()
        if not scheduling.is_due(schedule, today):
            print(f"{today:%d/%m/%Y}: ainda não é o primeiro dia útil do mês; nada a fazer.")
            return EXIT_OK
        month = closing.previous_month()
        marker = closing.done_marker(config.settings.output_dir, month)
        if marker.exists():  # o disparo dos dias seguintes (ou a recuperação de horário perdido) não repete
            print(f"Fechamento de {month} já feito ({marker}); nada a fazer.")
            return EXIT_OK
        return _month_close(config, None, f"agendamento:{schedule.name}")
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


def cmd_ia_set_key(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.reports.ai import API_KEY_SECRET

    key = getpass.getpass("Chave da API do Claude (não será exibida): ").strip()
    if not key.startswith("sk-ant-"):
        raise CredentialError("Chave inválida (esperado texto iniciado por sk-ant-). Nada foi alterado.")
    _store(config).set_secret(API_KEY_SECRET, key)
    _audit(config, "ia_chave_cadastrada")
    print("Chave da API do Claude gravada no cofre. Use: jervis customers report <cliente> --ia")
    return EXIT_OK


def cmd_ia_delete_key(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.reports.ai import API_KEY_SECRET

    removed = _store(config).delete_secret(API_KEY_SECRET)
    _audit(config, "ia_chave_removida")
    print("Chave removida do cofre." if removed else "Não havia chave cadastrada.")
    return EXIT_OK


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
    notifier = Notifier(config.notifications, _store(config))
    if args.status:  # prévia do aviso de uma coleta
        manifest = {
            "id": "teste", "origem": "teste de notificação", "ambiente": config.environment, "estado": "concluida",
            "status": args.status, "plataformas": {"exemplo": {"status": args.status, "contagens": {"registros": 0}}},
        }
        errors = notifier.notify(manifest, Path(config.settings.output_dir), force=True)
    else:
        who = actor()
        errors = notifier.send_message(
            "[Jervis3000] Teste de notificação",
            f"Mensagem de teste enviada por {who['usuario']} em {who['maquina']} ({datetime.now():%d/%m/%Y %H:%M}).\n"
            "Os avisos das coletas e do fechamento mensal dos relatórios chegarão por aqui.")
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


# --- banco de dados ----------------------------------------------------------------------


def _ensure_tables(config: AppConfig) -> None:
    """Ponto de entrada: cria as tabelas que não existem. Banco fora do ar não impede os demais comandos."""
    try:
        created = db.ensure_schema(config.database, _store(config))
    except db.DatabaseError as exc:
        print(f"Atenção: tabelas do banco não verificadas: {redact(str(exc))}", file=sys.stderr)
        return
    if created:
        print(f"Estrutura do banco '{config.database.name}' atualizada: {', '.join(created)}")
        _audit(config, "banco_tabelas_criadas", banco=config.database.name, tabelas=created)


def _require_database(config: AppConfig):
    if not config.database:
        raise ConfigError("Banco não configurado: inclua a seção 'database' (host, port, name) no arquivo de configuração.")
    return config.database


def cmd_db_init(args: argparse.Namespace, config: AppConfig) -> int:
    database = _require_database(config)
    created = db.ensure_schema(database, _store(config))
    if created:
        _audit(config, "banco_tabelas_criadas", banco=database.name, tabelas=created)
    print(f"Banco '{database.name}' em {database.host}:{database.port}: "
          + (f"criado: {', '.join(created)}." if created else "tabelas e colunas já existiam."))
    return EXIT_OK


def cmd_db_status(args: argparse.Namespace, config: AppConfig) -> int:
    database = _require_database(config)
    status = db.table_status(database, _store(config))
    print(f"Conexão OK: {database.host}:{database.port}, banco '{database.name}'.")
    _print_table(["TABELA", "LINHAS"], [[name, "não existe" if n is None else str(n)] for name, n in status.items()])
    store = _store(config)
    try:
        crypto.load_key(store)
        print("Chave de criptografia da chave MFA: cadastrada.")
    except crypto.EncryptionKeyError:
        print("Chave de criptografia da chave MFA: ausente (jervis db generate-key).")
    return EXIT_OK


def cmd_db_set_credentials(args: argparse.Namespace, config: AppConfig) -> int:
    username = args.username or input("Usuário do MySQL: ").strip()
    password = getpass.getpass("Senha do MySQL: ")
    if not username or not password or password != getpass.getpass("Confirme a senha: "):
        raise CredentialError("Usuário vazio ou senhas que não conferem. Nada foi alterado.")
    store = _store(config)
    store.set(db.CREDENTIALS_NAME, username, password)
    _audit(config, "banco_credencial_cadastrada", usuario=mask_username(username))
    print(f"Credenciais do banco salvas no cofre do sistema ({store.backend_name()}).")
    if store.status(db.CREDENTIALS_NAME).source == "env":
        print(f"Atenção: as variáveis {env_prefix(db.CREDENTIALS_NAME)}* estão definidas e têm prioridade sobre o cofre.")
    return EXIT_OK


def cmd_db_generate_key(args: argparse.Namespace, config: AppConfig) -> int:
    store = _store(config)
    if store.get_secret(crypto.VAULT_KEY) and not args.force:
        raise ConfigError("Já existe uma chave de criptografia no cofre. Substituí-la deixa ilegíveis as chaves MFA já "
                          "gravadas no banco; se for isso mesmo, use --force.")
    store.set_secret(crypto.VAULT_KEY, crypto.new_key())
    _audit(config, "banco_chave_mfa_gerada", substituida=bool(args.force))
    print("Chave de criptografia gerada e salva no cofre do sistema. Faça uma cópia segura dela: sem ela, "
          "as chaves MFA gravadas no banco não podem ser lidas.")
    return EXIT_OK


# --- cadastro de clientes e serviços --------------------------------------------------


@contextlib.contextmanager
def _db(config: AppConfig):
    """Conexão com commit ao final (ou rollback em caso de erro)."""
    conn = db.connect(_require_database(config), _store(config))
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _settings_from(pairs: list[str]) -> dict:
    settings = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        key = key.strip()
        if not sep or not key:
            raise ConfigError(f"Use CHAVE=VALOR em --set (recebido: '{pair}').")
        if key.lower() in FORBIDDEN_KEYS:
            raise ConfigError(f"'{key}' parece uma credencial: credenciais não ficam nas configurações do serviço.")
        try:
            settings[key] = json.loads(value)  # números, true/false, listas e objetos JSON
        except json.JSONDecodeError:
            settings[key] = value
    return settings


def _checked_class(identifier: str) -> str:
    identifier = (identifier or "").strip()
    if not identifier:
        raise ConfigError("Informe a classe do coletor em --class.")
    known = sorted(set(COLLECTORS) | api_credentials.API_CLASSES)
    if identifier not in known and "." not in identifier:
        raise ConfigError(f"Classe '{identifier}' desconhecida. Use um destes tipos: {', '.join(known)}, "
                          "ou o caminho completo da classe (pacote.modulo.Classe).")
    return identifier


def _services_label(customer: repository.Customer) -> str:
    def label(slug):
        text = f"{slug} → {customer.external[slug]}" if slug in customer.external else slug
        return f"{text} (MFA própria)" if slug in customer.with_mfa else text
    return ", ".join(label(slug) for slug in customer.services) or "—"


def _prompt_mfa(store) -> str:
    """Pede a chave MFA (oculta), valida e devolve já criptografada."""
    key = crypto.load_key(store)  # antes de pedir o segredo: sem chave, nem pergunta
    secret = normalize_totp_secret(getpass.getpass("Chave MFA (segredo TOTP base32, não será exibida): "))
    if not is_valid_totp_secret(secret):
        raise CredentialError("Chave MFA inválida (esperado texto base32, ex.: JBSWY3DPEHPK3PXP). Nada foi alterado.")
    return crypto.encrypt_secret(secret, key)


def cmd_customers_add(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        customer_id = repository.add_customer(conn, args.name, args.desk_manager_id)
    _audit(config, "cliente_cadastrado", cliente=args.name.strip(), id=customer_id, desk_manager_id=args.desk_manager_id)
    print(f"Cliente '{args.name.strip()}' cadastrado (id {customer_id}).")
    return EXIT_OK


def cmd_customers_list(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        customers = repository.list_customers(conn)
    if not customers:
        print("Nenhum cliente cadastrado. Use 'jervis customers add \"NOME\"'.")
        return EXIT_OK
    _print_table(["ID", "CLIENTE", "ATIVO", "DESK MANAGER", "SERVIÇOS"],
                 [[str(c.id), c.name, "sim" if c.active else "não", c.desk_manager_id or "—", _services_label(c)] for c in customers])
    inactive = sum(1 for c in customers if not c.active)
    print(f"\n{len(customers)} cliente(s)" + (f", {inactive} inativo(s) (fora do fechamento mensal)." if inactive else "."))
    return EXIT_OK


def cmd_customers_show(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        c = repository.find_customer(conn, args.customer)
    print(f"Cliente: {c.name} (id {c.id})\nDesk Manager: {c.desk_manager_id or '—'}\n"
          f"Situação: {'ativo' if c.active else 'inativo' + (f' ({c.inactive_reason})' if c.inactive_reason else '') + ' — fora do fechamento mensal'}")
    if not c.services:
        print("Serviços: nenhum (use 'jervis customers link')")
        return EXIT_OK
    print()
    _print_table(["SERVIÇO", "NOME NA PLATAFORMA", "PRODUTOS CONTRATADOS", "DISPOSITIVOS", "MFA"],
                 [[slug, c.external.get(slug) or f"{c.name} (nome do cadastro)",
                   "; ".join((c.contracts.get(slug) or {}).get("produtos") or []) or "—",
                   str((c.contracts.get(slug) or {}).get("dispositivos") or "—"),
                   "própria do cliente" if slug in c.with_mfa else "a da conta de parceiro"] for slug in c.services])
    return EXIT_OK


def cmd_customers_update(args: argparse.Namespace, config: AppConfig) -> int:
    if args.name is None and args.desk_manager_id is None:
        raise ConfigError("Informe --name e/ou --desk-manager-id.")
    with _db(config) as conn:
        c = repository.update_customer(conn, args.customer, args.name, args.desk_manager_id)
    _audit(config, "cliente_alterado", id=c.id, nome=args.name, desk_manager_id=args.desk_manager_id)
    print(f"Cliente atualizado: {c.name} (id {c.id}), Desk Manager: {c.desk_manager_id or '—'}.")
    return EXIT_OK


def cmd_customers_remove(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        c = repository.find_customer(conn, args.customer)
        if not args.yes:
            extra = f" e {len(c.services)} vínculo(s) ({', '.join(c.services)})" if c.services else ""
            if input(f"Remover o cliente '{c.name}' (id {c.id}){extra}? [s/N] ").strip().lower() not in ("s", "sim"):
                print("Nada foi removido.")
                return EXIT_OK
        repository.remove_customer(conn, str(c.id))
    _audit(config, "cliente_removido", cliente=c.name, id=c.id, servicos=c.services)
    print(f"Cliente '{c.name}' removido" + (f", com os vínculos: {', '.join(c.services)}." if c.services else "."))
    return EXIT_OK


def cmd_customers_deactivate(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        c = repository.set_active(conn, args.customer, False, args.reason)
    _audit(config, "cliente_inativado", cliente=c.name, id=c.id, motivo=c.inactive_reason)
    print(f"{c.name} (id {c.id}) inativado" + (f" ({c.inactive_reason})" if c.inactive_reason else "")
          + ": fica fora do fechamento mensal e do 'customers report --all'.")
    return EXIT_OK


def cmd_customers_activate(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        c = repository.set_active(conn, args.customer, True)
    _audit(config, "cliente_reativado", cliente=c.name, id=c.id)
    print(f"{c.name} (id {c.id}) reativado.")
    return EXIT_OK


def cmd_customers_merge(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        source, target = repository.find_customer(conn, args.source), repository.find_customer(conn, args.target)
        if not args.yes:
            print(f"Origem:  {source.name} (id {source.id}) — {_services_label(source)}")
            print(f"Destino: {target.name} (id {target.id}) — {_services_label(target)}")
            answer = input(f"Mover os vínculos e o histórico de '{source.name}' para '{target.name}' e apagar a origem? [s/N] ")
            if answer.strip().lower() not in ("s", "sim"):
                print("Nada foi alterado.")
                return EXIT_OK
        source, target, moved = repository.merge_customers(conn, str(source.id), str(target.id))
    _audit(config, "clientes_unidos", origem=source.name, origem_id=source.id, destino=target.name, destino_id=target.id,
           servicos=moved)
    print(f"'{source.name}' unido a '{target.name}' (id {target.id}). Serviços agora: {_services_label(target)}")
    return EXIT_OK


def cmd_customers_duplicates(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.api import sync

    with _db(config) as conn:
        customers = repository.list_customers(conn)
    active = [c for c in customers if c.active]
    pairs = sync.probable_duplicates(active)
    if pairs:
        print("Prováveis cadastros do mesmo cliente:")
        for a, b in pairs:
            same = sorted(set(a.services) & set(b.services))
            hint = (f"mesmo serviço ({', '.join(same)}): desative o que sobra" if same
                    else f"jervis customers merge {a.id} {b.id}  (ou {b.id} {a.id})")
            print(f"  {a.name} (id {a.id}: {', '.join(a.services) or '—'})  ×  {b.name} (id {b.id}: {', '.join(b.services) or '—'})")
            print(f"      → {hint}")
    tests = [c for c in active if sync.looks_like_test(c.name)]
    if tests:
        print("\nCom cara de POC, trial ou teste:")
        for c in tests:
            print(f"  {c.name} (id {c.id}) → jervis customers deactivate {c.id} --reason \"...\"")
    if not pairs and not tests:
        print("Nenhum provável duplicado ou cliente de teste entre os ativos.")
    else:
        print("\nSão sugestões pelo nome: confira antes de unir ou inativar.")
    return EXIT_OK


def cmd_customers_link(args: argparse.Namespace, config: AppConfig) -> int:
    token = _prompt_mfa(_store(config)) if args.mfa else None if args.clear_mfa else repository.KEEP
    external = repository.KEEP if args.external_name is None else args.external_name
    products = repository.KEEP if args.products is None else args.products
    contracted = repository.KEEP if args.contracted is None else (args.contracted or None)
    if args.contracted is not None and args.contracted < 0:
        raise ConfigError("--contracted deve ser zero ou positivo.")
    with _db(config) as conn:
        customer, service, created = repository.link(conn, args.customer, args.service, token, external, products, contracted)
    mfa = "cadastrada" if args.mfa else "removida" if args.clear_mfa else None
    _audit(config, "vinculo_criado" if created else "vinculo_alterado", cliente=customer.name, servico=service.slug,
           nome_na_plataforma=customer.name_on(service.slug), **({"chave_mfa": mfa} if mfa else {}))
    print(f"{customer.name} ↔ {service.slug}: vínculo {'criado' if created else 'atualizado'}; "
          f"nome na plataforma: {customer.name_on(service.slug)}"
          + (f"; chave MFA própria {mfa} (criptografada)." if mfa == "cadastrada" else f"; chave MFA própria {mfa}." if mfa else "."))
    return EXIT_OK


def _report_formats(text: str | None) -> list[str] | None:
    if not text:
        return None
    formats = [f.strip().lower() for f in text.split(",") if f.strip()]
    invalid = [f for f in formats if f not in REPORT_FORMATS]
    if invalid:
        raise ConfigError(f"Formato(s) inválido(s): {', '.join(invalid)}. Opções: {', '.join(REPORT_FORMATS)}.")
    return formats


def cmd_customers_report(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.api import closing, collect
    from jervis.api.run import reportable_customers, run_customer

    if bool(args.customer) == bool(args.all_customers):
        raise ConfigError("Informe um cliente ou --all.")
    if args.all_customers and (args.notes or args.open):
        raise ConfigError("--notes e --open valem para um cliente só (com --all, as notas vêm de notas/<cliente>/).")
    formats = _report_formats(args.formats)
    if args.days is not None:
        if args.days <= 0:
            raise ConfigError("--days deve ser um número positivo de dias.")
        period = collect.last_days(args.days)
    else:
        try:
            period = collect.month(args.month)  # sem --month: o mês atual, até hoje
        except ValueError as exc:
            raise ConfigError(f"--month: {exc}") from exc
    notes = Path(args.notes) if args.notes else None
    if notes and not notes.is_file():
        raise ConfigError(f"Arquivo de notas não encontrado: {notes}")
    if args.all_customers:
        return _report_all(config, reportable_customers, run_customer, period, formats, args.ia)
    with _db(config) as conn:
        run = run_customer(config, _store(config), conn, args.customer, period=period, formats=formats, notes=notes,
                           ai=args.ia)
        outcome, report_id = closing.record(conn, run, period, "manual", actor()["usuario"])
    statuses = {r.platform: r.status for r in run.results}
    _audit(config, "relatorio_cliente", cliente=run.customer.name, execucao=str(run.run_dir), plataformas=statuses,
           revisao=report_id)
    print(f"\nRelatório em {run.run_dir}")
    if outcome != "falha":
        print(f"Registrado para revisão (#{report_id}). Aprovar: jervis reviews approve \"{run.customer.name}\"")
    if args.open and run.files.get("html"):
        _open_file(run.files["html"][0])
    return EXIT_OK if outcome == "sucesso" else 2


def _report_all(config: AppConfig, reportable_customers, run_customer, period, formats, ai: bool,
                origin: str = "manual") -> int:
    """Relatório de cada cliente vinculado, um após o outro (a falha de um não interrompe os demais), cada um
    registrado para revisão."""
    from jervis.api import closing

    with _db(config) as conn:
        customers = reportable_customers(conn)
        if not customers:
            print("Nenhum cliente vinculado a Acronis, Sophos ou Zabbix. Veja 'jervis services clients acronis --import'.")
            return EXIT_OK
        print(f"{len(customers)} cliente(s): {', '.join(c.name for c in customers)}\n")
        outcomes = closing.run_customers(config, _store(config), conn, customers, period, run_customer, formats, ai,
                                         origin, actor()["usuario"])
    _print_outcomes(config, outcomes)
    return EXIT_OK if all(o.resultado == "sucesso" for o in outcomes) else 2


def _print_outcomes(config: AppConfig, outcomes) -> None:
    for o in outcomes:
        _audit(config, "relatorio_cliente", cliente=o.customer, execucao=str(o.run_dir) if o.run_dir else None,
               resultado=o.resultado, revisao=o.report_id)
    print("\nResumo:")
    _print_table(["REVISÃO", "CLIENTE", "SITUAÇÃO", "PASTA / MOTIVO"],
                 [[f"#{o.report_id}" if o.report_id else "—", o.customer, o.resultado,
                   str(o.run_dir) if o.run_dir and o.resultado != "falha" else o.detalhe] for o in outcomes])
    pending = sum(1 for o in outcomes if o.resultado != "falha")
    if pending:
        print(f"\n{pending} relatório(s) aguardando revisão: jervis reviews list")


def cmd_month_close(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.api import closing, collect

    month = args.month or closing.previous_month()
    try:
        collect.month(month)
    except ValueError as exc:
        raise ConfigError(f"--month: {exc}") from exc
    return _month_close(config, month, "manual", notify=not args.no_notify)


def _month_close(config: AppConfig, month: str | None, origin: str, notify: bool = True) -> int:
    from jervis.api import closing
    from jervis.api.run import reportable_customers, run_customer

    store = _store(config)
    notifier = Notifier(config.notifications, store) if notify else None
    if notify and not notifier.channels():
        print("Atenção: nenhum canal de notificação configurado (seção notifications); a equipe não será avisada.")
        notifier = None
    with _db(config) as conn:
        outcomes = closing.close_month(config, store, conn, notifier, run_customer, reportable_customers, month,
                                       origin=origin, user=actor()["usuario"])
    _audit(config, "fechamento_mensal", competencia=month or closing.previous_month(), origem=origin,
           clientes=len(outcomes), falhas=sum(1 for o in outcomes if o.resultado == "falha"))
    _print_outcomes(config, outcomes)
    return EXIT_OK if all(o.resultado == "sucesso" for o in outcomes) else 2


def _local(moment) -> str:
    """Data do banco (UTC, sem fuso) no horário desta máquina."""
    if not moment:
        return "—"
    return f"{moment.replace(tzinfo=timezone.utc).astimezone():%d/%m %H:%M}"


_REVIEW_LABEL = {"pendente": "pendente", "aprovado": "aprovado", "rejeitado": "rejeitado", "substituido": "substituído",
                 "falha": "falha"}


def cmd_reviews_list(args: argparse.Namespace, config: AppConfig) -> int:
    status = None if args.status == "todos" else args.status
    with _db(config) as conn:
        reports = repository.list_reports(conn, status, args.month)
    if not reports:
        print("Nenhum relatório" + (f" {_REVIEW_LABEL[status]}" if status else "") + (f" em {args.month}" if args.month else "") + ".")
        return EXIT_OK
    _print_table(["REVISÃO", "CLIENTE", "COMPETÊNCIA", "RESULTADO", "SITUAÇÃO", "GERADO EM", "REVISADO POR", "PASTA / OBSERVAÇÃO"],
                 [[f"#{r.id}", r.customer, r.competencia or r.periodo, r.resultado, _REVIEW_LABEL.get(r.status, r.status),
                   _local(r.gerado_em), r.revisado_por or "—",
                   r.run_dir if r.status in ("pendente", "aprovado") and r.run_dir else (r.observacao or "—")] for r in reports])
    print(f"\n{len(reports)} relatório(s).")
    if status == "pendente":
        print("Abrir: jervis reviews open <cliente> | Aprovar: jervis reviews approve <cliente> | "
              "Rejeitar: jervis reviews reject <cliente> --reason \"...\"")
    return EXIT_OK


def _review(args: argparse.Namespace, config: AppConfig, status: str, note: str | None) -> int:
    reviewer = actor()["usuario"]
    with _db(config) as conn:
        report = repository.find_report(conn, args.report, args.month)
        repository.review_report(conn, report.id, status, reviewer, note)
    _audit(config, f"relatorio_{status}", revisao=report.id, cliente=report.customer, competencia=report.competencia,
           pasta=report.run_dir, observacao=note)
    label = "aprovado" if status == "aprovado" else "rejeitado"
    print(f"Relatório #{report.id} de {report.customer} ({report.competencia or report.periodo}) {label} por {reviewer}.")
    if status == "aprovado" and report.run_dir:
        folder = Path(report.run_dir)
        files = [folder / name for name in ("relatorio_executivo.pdf", "relatorio_mensal.pdf") if (folder / name).exists()]
        print("Arquivos para enviar ao cliente:")
        for f in files or [folder]:
            print(f"  {f}")
    elif status == "rejeitado":
        print(f"Para gerar de novo: jervis customers report \"{report.customer}\"" + (f" --month {report.competencia}" if report.competencia else ""))
    return EXIT_OK


def cmd_reviews_approve(args: argparse.Namespace, config: AppConfig) -> int:
    return _review(args, config, "aprovado", args.note)


def cmd_reviews_reject(args: argparse.Namespace, config: AppConfig) -> int:
    if not args.reason.strip():
        raise ConfigError("Informe o motivo da rejeição em --reason.")
    return _review(args, config, "rejeitado", args.reason.strip())


def cmd_reviews_open(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        report = repository.find_report(conn, args.report, args.month)
    if not report.run_dir or not Path(report.run_dir).is_dir():
        raise ConfigError(f"A pasta do relatório #{report.id} não existe mais: {report.run_dir or '—'}.")
    folder = Path(report.run_dir)
    target = folder / "relatorio_executivo.pdf"
    _open_file(target if target.exists() else folder)
    print(f"Aberto: {target if target.exists() else folder}")
    return EXIT_OK


def cmd_customers_unlink(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        customer, service = repository.unlink(conn, args.customer, args.service)
    _audit(config, "vinculo_removido", cliente=customer.name, servico=service.slug)
    print(f"{customer.name} desvinculado de {service.slug}.")
    return EXIT_OK


def cmd_services_add(args: argparse.Namespace, config: AppConfig) -> int:
    url = validate_url(args.url, args.slug)
    cls, settings = _checked_class(args.class_identifier), _settings_from(args.set)
    with _db(config) as conn:
        service_id = repository.add_service(conn, args.slug, url, cls, settings)
    _audit(config, "servico_cadastrado", servico=args.slug, id=service_id, url=url, classe=cls, configuracoes=sorted(settings))
    print(f"Serviço '{args.slug}' cadastrado (id {service_id}).")
    return EXIT_OK


def cmd_services_list(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        services = repository.list_services(conn)
    if not services:
        print("Nenhum serviço cadastrado. Use 'jervis services add <slug> --url ... --class ...'.")
        return EXIT_OK
    store = _store(config)

    def login(slug):
        try:
            return "cofre" if store.status(slug).configured else "ausente"
        except CredentialError:
            return "erro no cofre"

    def api(service):
        if service.class_identifier not in api_credentials.API_CLASSES:
            return "—"
        return "cofre" if api_credentials.configured(store, service.slug, service.class_identifier) else "ausente"

    _print_table(["ID", "SLUG", "CLASSE", "CLIENTES", "API", "URL", "CONFIGURAÇÕES"],
                 [[str(s.id), s.slug, s.class_identifier, str(s.customers), api(s), s.url,
                   json.dumps(s.settings, ensure_ascii=False) if s.settings else "—"] for s in services])
    return EXIT_OK


def cmd_services_update(args: argparse.Namespace, config: AppConfig) -> int:
    if not (args.url or args.class_identifier or args.set or args.unset or args.mfa or args.clear_mfa):
        raise ConfigError("Informe --url, --class, --set, --unset, --mfa e/ou --clear-mfa.")
    url = validate_url(args.url, args.slug) if args.url else None
    cls = _checked_class(args.class_identifier) if args.class_identifier else None
    token = _prompt_mfa(_store(config)) if args.mfa else None
    with _db(config) as conn:
        s = repository.update_service(conn, args.slug, url, cls, _settings_from(args.set), args.unset)
        if args.mfa or args.clear_mfa:
            s = repository.set_service_mfa(conn, args.slug, token)
    mfa = "cadastrada" if args.mfa else "removida" if args.clear_mfa else None
    _audit(config, "servico_alterado", servico=s.slug, url=url, classe=cls, alteradas=sorted(_settings_from(args.set)),
           removidas=args.unset, **({"chave_mfa": mfa} if mfa else {}))
    if mfa:
        print(f"Chave MFA da conta de parceiro {mfa}" + (" (criptografada)." if args.mfa else "."))
    print(f"Serviço '{s.slug}' atualizado: {s.url} · {s.class_identifier} · "
          f"{json.dumps(s.settings, ensure_ascii=False) if s.settings else 'sem configurações extras'}")
    return EXIT_OK


def cmd_services_set_api_credentials(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        service = repository.find_service(conn, args.slug)
    fields = api_credentials.fields_for(service.class_identifier)
    values = {}
    for field in fields:
        prompt = f"{field.label}" + (" (não será exibida): " if field.secret else ": ")
        value = (getpass.getpass(prompt) if field.secret else input(prompt)).strip()
        if not value:
            raise CredentialError(f"{field.label} vazio. Nada foi alterado.")
        values[field.name] = value
    store = _store(config)
    api_credentials.save(store, service.slug, service.class_identifier, values)
    _audit(config, "servico_api_credencial_cadastrada", servico=service.slug, campos=[f.name for f in fields])
    print(f"Credenciais de API de '{service.slug}' salvas no cofre do sistema. Teste com: jervis services test-api {service.slug}")
    return EXIT_OK


def cmd_services_test_api(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.api import factory

    with _db(config) as conn:
        service = repository.find_service(conn, args.slug)
    try:
        detail = factory.build(service, _store(config)).check()
    except ApiError as exc:
        print(f"[FALHA] {service.slug}: {redact(str(exc))}")
        return EXIT_FAILURE
    print(f"[OK] {service.slug}: {detail}")
    return EXIT_OK


def cmd_services_clients(args: argparse.Namespace, config: AppConfig) -> int:
    from jervis.api import factory, sync

    with _db(config) as conn:
        service = repository.find_service(conn, args.slug)
        api = factory.build(service, _store(config))
        if not hasattr(api, "customer_names"):
            raise ConfigError(f"O serviço '{service.slug}' ({service.class_identifier}) não lista clientes por API.")
        try:
            names = api.customer_names()
        except ApiError as exc:
            print(f"[FALHA] {service.slug}: {redact(str(exc))}")
            return EXIT_FAILURE
        try:
            aliases = api.customer_aliases() if hasattr(api, "customer_aliases") else {}
        except ApiError as exc:
            print(f"[FALHA] {service.slug}: {redact(str(exc))}")
            return EXIT_FAILURE
        customers = repository.list_customers(conn)
        rows = sync.compare(names, customers, service.slug, aliases)
        if args.only:
            wanted = {n.strip().lower() for n in args.only}
            rows = [r for r in rows if r.name.lower() in wanted]
            missing = wanted - {r.name.lower() for r in rows}
            if missing:
                raise ConfigError(f"Não encontrado(s) em {service.slug}: {', '.join(sorted(missing))}.")
        _print_table(["CLIENTE NA PLATAFORMA", "SITUAÇÃO", "CLIENTE NO JERVIS"],
                     [[r.name, r.status, f"{r.customer.name} (id {r.customer.id})" if r.customer else "—"] for r in rows])
        counts = {status: sum(r.status == status for r in rows) for status in (sync.LINKED, sync.UNLINKED, sync.NEW, sync.AMBIGUOUS)}
        print(f"\n{len(rows)} cliente(s) em {service.slug}: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
        if not args.only:
            for c in sync.orphans(names, customers, service.slug, aliases):
                print(f"Atenção: {c.name} está vinculado a {service.slug} como '{c.name_on(service.slug)}', que não existe "
                      f"na plataforma. Ajuste com 'jervis customers link {c.id} {service.slug} --external-name ...'.")
        if counts[sync.AMBIGUOUS]:
            print("Nomes repetidos no cadastro não são importados: vincule com 'jervis customers link <id> ...'.")
        pending = [r for r in rows if r.status in (sync.NEW, sync.UNLINKED)]
        if not args.do_import:
            if pending:
                print(f"Para cadastrar e vincular os {len(pending)} que faltam: jervis services clients {service.slug} --import")
            return EXIT_OK
        if not pending:
            print("Nada a importar.")
            return EXIT_OK
        question = f"Cadastrar/vincular {len(pending)} cliente(s) a {service.slug}? [s/N] "
        if not args.yes and input(question).strip().lower() not in ("s", "sim"):
            print("Nada foi alterado.")
            return EXIT_OK
        done = sync.import_missing(conn, pending, service.slug)
    created = [name for name, new in done if new]
    _audit(config, "clientes_importados", servico=service.slug, cadastrados=created, vinculados=[name for name, _ in done])
    print(f"{len(done)} vínculo(s) criado(s) com {service.slug} ({len(created)} cliente(s) novo(s) no cadastro).")
    return EXIT_OK


def cmd_services_set_credentials(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        service = repository.find_service(conn, args.slug)  # só para serviço cadastrado
    username = args.username or input(f"Usuário da conta de parceiro em {service.slug}: ").strip()
    password = getpass.getpass("Senha: ")
    if not username or not password or password != getpass.getpass("Confirme a senha: "):
        raise CredentialError("Usuário vazio ou senhas que não conferem. Nada foi alterado.")
    store = _store(config)
    store.set(service.slug, username, password)
    _audit(config, "servico_credencial_cadastrada", servico=service.slug, usuario=mask_username(username))
    print(f"Credenciais da conta de parceiro em '{service.slug}' salvas no cofre do sistema ({store.backend_name()}).")
    if store.status(service.slug).source == "env":
        print(f"Atenção: as variáveis {env_prefix(service.slug)}* estão definidas e têm prioridade sobre o cofre.")
    return EXIT_OK


def cmd_services_remove(args: argparse.Namespace, config: AppConfig) -> int:
    with _db(config) as conn:
        s = repository.remove_service(conn, args.slug)
    _audit(config, "servico_removido", servico=s.slug, id=s.id)
    print(f"Serviço '{s.slug}' removido.")
    return EXIT_OK


# Não disparam a criação automática das tabelas: preparam o acesso (credenciais/chave podem não existir
# ainda), criam as tabelas explicitamente ou só observam.
_DB_SETUP_COMMANDS = (cmd_db_init, cmd_db_status, cmd_db_set_credentials, cmd_db_generate_key)


# --- driver do navegador --------------------------------------------------------------


def _prepare_driver(config: AppConfig) -> None:
    driver.prepare(config.settings, print, lambda event, **details: _audit(config, event, **details))


def cmd_driver_status(args: argparse.Namespace, config: AppConfig) -> int:
    settings = config.settings
    if settings.browser != "edge":
        print(f"Navegador configurado: {settings.browser}. A verificação do driver só está disponível para o Edge.")
        return EXIT_OK
    info = driver.status(settings)
    origin = "settings.driver_path" if settings.driver_path else "padrão; settings.driver_path vazio"
    print(f"Microsoft Edge instalado: {info.edge_version or 'não encontrado'}")
    print(f"Driver: {info.path} ({origin})")
    print(f"Versão do driver: {info.driver_version or 'não encontrado'}")
    print(f"Atualização automática antes das coletas: {'ativa' if settings.driver_auto_update else 'desativada'}")
    if info.compatible:
        exact = "" if info.driver_version == info.edge_version else " (mesma versão principal)"
        print(f"Situação: compatível{exact}.")
        return EXIT_OK
    print("Situação: INCOMPATÍVEL. Atualize com: jervis driver update")
    return 2


def cmd_driver_update(args: argparse.Namespace, config: AppConfig) -> int:
    settings = config.settings
    result = driver.update_for(settings, force=args.force)
    if result.updated:
        print(f"Driver atualizado: {result.previous or 'nenhum'} -> {result.current} (Edge {result.edge_version}) em {result.path}")
        _audit(config, "driver_atualizado", de=result.previous, para=result.current, edge=result.edge_version, caminho=str(result.path))
    else:
        print(f"Driver já está na versão do Edge ({result.current}) em {result.path}.")
    changes = {}
    if not settings.driver_path:
        settings.driver_path = changes["driver_path"] = result.path.as_posix()
    if args.auto is not None and args.auto != settings.driver_auto_update:
        settings.driver_auto_update = changes["driver_auto_update"] = args.auto
    if changes:
        save_config(config)
        _audit(config, "configuracao_alterada", alteracoes=changes)
        print("Configuração atualizada: " + ", ".join(f"{k} = {v}" for k, v in changes.items()))
    if not settings.driver_auto_update:
        print("Dica: 'jervis driver update --auto' faz essa verificação sozinha antes de cada coleta.")
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

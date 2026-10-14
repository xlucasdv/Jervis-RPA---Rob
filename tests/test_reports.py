import csv
import io
import json
from datetime import datetime

import pytest
from openpyxl import load_workbook

from jervis import cli
from jervis.config import Settings
from jervis.consolidation import consolidate
from jervis.reports import excel, generate_reports
from jervis.reports.data import executive_summary
from jervis.reports.html import format_datetime

COLLECTED = "2026-10-06T12:00:00-03:00"


def result(platform, kind, datasets, issues=(), status="sucesso"):
    return {"platform": platform, "kind": kind, "environment": "producao", "started_at": COLLECTED,
            "finished_at": COLLECTED, "status": status, "counts": {k: len(v) for k, v in datasets.items()},
            "summary": {}, "issues": list(issues), "datasets": datasets}


def host(nome, disponibilidade="disponivel"):
    return {"nome": nome, "disponibilidade": disponibilidade, "monitorado": True, "status_monitoramento": "Enabled",
            "interfaces_monitoradas": "ZBX", "origem": "monitoramento"}


def task(device, situacao, status="Sucesso"):
    return {"nome_tarefa": "Backup diário", "dispositivo": device, "status_backup": status, "ultima_execucao": "x",
            "ultima_execucao_iso": "2026-10-06T09:00-03:00", "situacao_backup": situacao,
            "motivo": None if situacao == "ok" else f"Backup {situacao}", "origem": "atividade"}


@pytest.fixture
def consolidated():
    return consolidate([
        result("sophos", "sophos", {
            "dispositivos": [
                {"nome": "PC-01", "status_agente": "Ativo", "situacao_protecao": "Protegido",
                 "ultima_comunicacao_iso": "2026-10-06T10:00-03:00", "origem": "computador"},
                {"nome": "SRV-FS01", "status_agente": "Bad", "situacao_protecao": "Not protected",
                 "ultima_comunicacao_iso": "2026-10-06T10:00-03:00", "origem": "servidor"},
            ],
            "alertas": [
                {"tipo": "<script>alert('x')</script> Malware", "severidade": "alta", "dispositivo": "PC-01",
                 "data_hora_iso": "2026-10-06T08:00-03:00", "situacao": "Open", "origem": "alerta"},
                {"tipo": "Antigo", "severidade": "media", "dispositivo": "PC-01",
                 "data_hora_iso": "2026-10-01T08:00-03:00", "situacao": "Resolved", "origem": "alerta"},
            ],
        }),
        result("acronis", "acronis", {"tarefas": [task("PC-01", "falha", "Falhou"), task("SRV-DB", "desatualizado"),
                                                  task("SRV-AD", "ok")]}),
        result("zabbix", "zabbix", {"hosts": [host("srv-db"), host("srv-web", "indisponivel"), host("pc-01")]}),
        result("legado", "zabbix", {}, status="falha", issues=[{
            "stage": "autenticacao", "category": "autenticacao", "message": "Acesso negado", "severity": "erro",
            "url": None, "screenshot": None, "timestamp": COLLECTED}]),
    ])


# --- 6.3 resumo executivo -----------------------------------------------------------------

def test_executive_indicators(consolidated):
    e = executive_summary(consolidated)
    # PC-01 aparece na Sophos e no Zabbix (pc-01): um único dispositivo no total.
    assert e["dispositivos"] == {"total": 4, "por_plataforma": {"sophos": 2, "zabbix": 3}}
    assert e["alertas"] == {"total": 2, "ativos": 1}
    assert e["criticos"] == 3  # SRV-FS01, alerta alta, backup com falha
    assert e["backups_com_falha"] == 1 and e["backups_em_atencao"] == 1
    assert e["hosts_indisponiveis"] == 1
    assert e["plataformas_sem_resposta"] == ["legado"] and e["plataformas_total"] == 4
    assert e["falhas_coleta"] == 1
    assert e["cobertura"]["backups"] == {"consultadas": 1, "sem_resposta": [], "com_dados": True}
    # "legado" é um Zabbix sem resposta, mas o outro Zabbix respondeu: há dados de hosts.
    assert e["cobertura"]["hosts"] == {"consultadas": 2, "sem_resposta": ["legado"], "com_dados": True}


def test_platform_without_data_gets_a_message_page(tmp_path):
    report = consolidate([
        result("sophos", "sophos", {"dispositivos": []}),
        result("acronis", "acronis", {}, status="falha", issues=[{
            "stage": "autenticacao", "category": "autenticacao", "message": "Acesso negado", "severity": "erro",
            "url": None, "screenshot": None, "timestamp": COLLECTED}]),
    ])
    generate_reports(report, tmp_path, ["html"], Settings())
    html = (tmp_path / "relatorio.html").read_text(encoding="utf-8")
    assert "Sem dados" in html and "Não foi possível coletar os dados desta plataforma" in html
    assert "NOCaaS" not in html  # Zabbix não consultado: sem página de monitoramento


# --- 6.1, 6.2, 6.5 HTML no padrão de apresentação ------------------------------------------

def test_html_follows_presentation_layout_and_escapes_platform_text(consolidated, tmp_path):
    meta = {"cliente": "Club Teste", "tipo": "Relatório Mensal", "periodo": "Julho de 2026", "periodo_curto": "Julho/2026"}
    generate_reports(consolidated, tmp_path, ["html"], Settings(), meta=meta)
    html = (tmp_path / "relatorio.html").read_text(encoding="utf-8")
    assert "RELATÓRIO MENSAL" in html and "Segurança e Monitoramento" in html and "Cliente: <b>Club Teste</b>" in html
    assert "Club Teste · Relatório Mensal — Julho/2026" in html  # rodapé de todas as páginas
    assert html.count('class="slide') >= 5 and '<span class="page">01</span>' in html
    assert "Sophos Central – Visão Geral" in html and "Acronis Cyber Protect – Visão Geral" in html  # página genérica
    assert "Recomendações Priorizadas" not in html or "badge" in html
    assert "Anexo – Itens Prioritários" in html
    assert "<script>alert(" not in html and "&lt;script&gt;alert(" in html  # texto vindo das plataformas é escapado
    assert "<script" not in html.split("</style>")[1]  # sem JavaScript: funciona igual no PDF


def test_format_datetime():
    assert format_datetime("2026-10-06T09:41:00-03:00") == "06/10/2026 09:41"
    assert format_datetime(None) == "—" and format_datetime("lixo") == "lixo"


# --- 6.4 Excel e CSV ----------------------------------------------------------------------

def test_excel_workbook(consolidated, tmp_path):
    output = generate_reports(consolidated, tmp_path, ["xlsx"], Settings())
    wb = load_workbook(output.files["xlsx"][0])
    assert wb.sheetnames == ["Resumo", "Consolidado", "sophos", "acronis", "zabbix", "legado", "Qualidade dos dados"]

    summary = {row[0]: row[1] for row in wb["Resumo"].iter_rows(min_row=5, max_row=12, max_col=2, values_only=True)}
    assert summary["Problemas críticos"] == 3 and summary["Plataformas sem resposta"] == 1

    sheet = wb["Consolidado"]
    header = [c.value for c in sheet[1]]
    assert header[:6] == ["Prioridade", "Classificação", "Plataforma", "Ambiente", "Categoria", "Recurso"]
    first = [c.value for c in sheet[2]]
    assert first[0] == 1 and first[1] == "Crítico"
    assert sheet.cell(2, 2).fill.fgColor.rgb.endswith("FDE7E7")  # cor da classificação
    assert isinstance(sheet.cell(2, 11).value, datetime)  # datas como datas do Excel
    assert sheet.freeze_panes == "C2" and sheet.auto_filter.ref
    assert wb["acronis"].max_row == 4  # cabeçalho + 3 tarefas


def test_excel_drops_control_characters():
    assert excel._clean("botnet null\x00\x13 0U digicert\x01") == "botnet null 0U digicert" and excel._clean(3) == 3


def test_csv_consolidated_and_per_platform(consolidated, tmp_path):
    output = generate_reports(consolidated, tmp_path, ["csv"], Settings())
    names = [p.name for p in output.files["csv"]]
    assert names == ["consolidado.csv", "relatorio_sophos.csv", "relatorio_acronis.csv", "relatorio_zabbix.csv", "relatorio_legado.csv"]
    rows = list(csv.DictReader(io.StringIO((tmp_path / "relatorio_zabbix.csv").read_text(encoding="utf-8-sig")), delimiter=";"))
    assert {r["plataforma"] for r in rows} == {"zabbix"} and len(rows) == 3


def test_failure_in_one_format_does_not_block_others(consolidated, tmp_path):
    settings = Settings(driver_path=str(tmp_path / "nao-existe.exe"))
    output = generate_reports(consolidated, tmp_path, ["html", "pdf", "xlsx"], settings)
    assert set(output.files) == {"html", "xlsx"}
    assert "Driver não encontrado" in output.errors["pdf"]
    assert not list(tmp_path.glob(".*impressao*"))  # arquivo temporário removido


@pytest.mark.browser
def test_pdf_printed_by_browser(consolidated, tmp_path, driver, test_driver_path):
    output = generate_reports(consolidated, tmp_path, ["pdf"], Settings(driver_path=test_driver_path))
    assert output.errors == {}
    pdf = output.files["pdf"][0].read_bytes()
    assert pdf.startswith(b"%PDF") and len(pdf) > 10_000


# --- CLI ----------------------------------------------------------------------------------

def test_cli_report_from_saved_run(consolidated, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["-c", "platforms.yaml", "init"])
    run_dir = tmp_path / "output" / "20261006-120000"
    run_dir.mkdir(parents=True)
    (run_dir / "zabbix.json").write_text(json.dumps(result("zabbix", "zabbix", {"hosts": [host("a")]})), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "report", "--formats", "html,xlsx"]) == 0
    out = capsys.readouterr().out
    assert "Consolidando" in out  # sem consolidado salvo: consolida antes
    assert "Relatório HTML: relatorio.html" in out and "Relatório XLSX: relatorio.xlsx" in out
    assert (run_dir / "relatorio.html").exists() and (run_dir / "consolidado.json").exists()


def test_cli_report_rejects_unknown_format(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["-c", "platforms.yaml", "init"])
    (tmp_path / "output" / "r1").mkdir(parents=True)
    (tmp_path / "output" / "r1" / "z.json").write_text(json.dumps(result("z", "zabbix", {})), encoding="utf-8")
    assert cli.main(["-c", "platforms.yaml", "report", "--formats", "docx"]) == 1
    assert "docx" in capsys.readouterr().err

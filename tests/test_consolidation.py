import csv
import io
import json

import pytest

from jervis import cli
from jervis.consolidation import Options, consolidate, latest_run_dir, load_run, write_outputs
from jervis.consolidation.cleaning import clean_value
from jervis.errors import ConfigError
from jervis.security import SecretStr

COLLECTED = "2026-10-06T12:00:00-03:00"


def result(platform, kind, datasets, issues=(), status="sucesso"):
    return {
        "platform": platform, "kind": kind, "environment": "producao", "started_at": "2026-10-06T11:58:00-03:00",
        "finished_at": COLLECTED, "status": status, "counts": {k: len(v) for k, v in datasets.items()},
        "summary": {}, "issues": list(issues), "datasets": datasets,
    }


def sophos_device(nome, agente="Ativo", protecao="Protegido", visto="2026-10-06T09:00-03:00", **extra):
    return {"nome": nome, "sistema_operacional": "Windows 11", "status_agente": agente, "situacao_protecao": protecao,
            "ultima_comunicacao": "06/10/2026 09:00", "ultima_comunicacao_iso": visto, "origem": "computador", **extra}


def sophos_alert(tipo, severidade, dispositivo="PC-1", situacao="Open", data="2026-10-06T08:00-03:00"):
    return {"tipo": tipo, "descricao": tipo, "severidade": severidade, "dispositivo": dispositivo,
            "data_hora": "Oct 6, 2026 8:00 AM", "data_hora_iso": data, "situacao": situacao, "origem": "alerta"}


def run(*results, options=None):
    report = consolidate(list(results), options)
    return report, {(r["categoria"], r["recurso"]): r for r in report["registros"]}


# --- 5.1 modelo padrão ------------------------------------------------------------------

def test_every_record_has_the_standard_fields():
    report, _ = run(
        result("sophos", "sophos", {"dispositivos": [sophos_device("PC-1")], "alertas": [sophos_alert("Malware", "alta")]}),
        result("acronis", "acronis", {"tarefas": [{"nome_tarefa": "Diário", "dispositivo": "SRV-1", "status_backup": "Sucesso",
                                                    "ultima_execucao": "x", "ultima_execucao_iso": COLLECTED,
                                                    "situacao_backup": "ok", "motivo": None, "origem": "atividade"}]}),
        result("zabbix", "zabbix", {"hosts": [{"nome": "srv-1", "disponibilidade": "disponivel", "monitorado": True,
                                               "status_monitoramento": "Enabled", "origem": "monitoramento"}]}),
    )
    expected = {"id", "prioridade", "classificacao", "plataforma", "tipo_plataforma", "ambiente", "categoria", "recurso",
                "status", "severidade", "mensagem", "data_evento", "data_coleta", "observacoes", "origem", "detalhes"}
    assert len(report["registros"]) == 4
    for rec in report["registros"]:
        assert set(rec) == expected
        assert rec["data_coleta"] == COLLECTED
    assert {r["categoria"] for r in report["registros"]} == {"endpoint", "alerta_seguranca", "tarefa_backup", "host"}
    assert report["registros"][0]["detalhes"]["tipo"] == "Malware"  # registro original preservado


# --- 5.3 classificação ------------------------------------------------------------------

def test_sophos_device_classification():
    _, recs = run(result("sophos", "sophos", {"dispositivos": [
        sophos_device("PC-OK"),
        sophos_device("PC-DESAT", protecao="Desatualizada"),
        sophos_device("PC-INATIVO", agente="Inativo"),
        sophos_device("SRV-BAD", agente="Bad", protecao="Not protected"),
        sophos_device("PC-SUMIDO", visto="2026-09-20T09:00-03:00"),
    ]}))
    cls = {name: r["classificacao"] for (_, name), r in recs.items()}
    assert cls == {"PC-OK": "normal", "PC-DESAT": "atencao", "PC-INATIVO": "indisponivel",
                   "SRV-BAD": "critico", "PC-SUMIDO": "indisponivel"}
    assert recs[("endpoint", "PC-SUMIDO")]["mensagem"] == "Sem comunicação há 16 dias."
    assert recs[("endpoint", "SRV-BAD")]["severidade"] == "alta"  # derivada da classificação


def test_stale_threshold_is_configurable():
    _, recs = run(result("sophos", "sophos", {"dispositivos": [sophos_device("PC", visto="2026-09-20T09:00-03:00")]}),
                  options=Options(stale_device_days=30))
    assert recs[("endpoint", "PC")]["classificacao"] == "normal"


def test_sophos_alert_classification():
    _, recs = run(result("sophos", "sophos", {"alertas": [
        sophos_alert("Malware", "alta", "PC-1"), sophos_alert("RTP off", "media", "PC-2"),
        sophos_alert("Info", "informativa", "PC-3"), sophos_alert("Velho", "alta", "PC-4", situacao="Resolved"),
    ]}))
    assert {k[1]: r["classificacao"] for k, r in recs.items()} == {
        "PC-1": "critico", "PC-2": "atencao", "PC-3": "normal", "PC-4": "normal"}


@pytest.mark.parametrize(
    "situacao, expected",
    [("falha", "critico"), ("sem_protecao", "critico"), ("nunca_executado", "critico"), ("incompleto", "atencao"),
     ("desatualizado", "atencao"), ("com_avisos", "atencao"), ("em_execucao", "normal"), ("ok", "normal")],
)
def test_acronis_classification(situacao, expected):
    _, recs = run(result("acronis", "acronis", {"dispositivos": [
        {"nome": "SRV-1", "status_protecao": "x", "situacao_backup": situacao, "motivo": "m", "ultimo_backup": None,
         "ultimo_backup_iso": None, "origem": "dispositivo"}]}))
    assert recs[("protecao_backup", "SRV-1")]["classificacao"] == expected


def test_acronis_task_uses_device_as_resource_and_reason_as_message():
    _, recs = run(result("acronis", "acronis", {"tarefas": [
        {"nome_tarefa": "Backup diário", "dispositivo": "PC-FIN", "status_backup": "Falhou",
         "ultima_execucao": "06/10/2026 09:41", "ultima_execucao_iso": "2026-10-06T09:41-03:00",
         "situacao_backup": "falha", "motivo": "Backup com falha (status: Falhou). Erro: Acesso negado",
         "origem": "atividade"}]}))
    rec = recs[("tarefa_backup", "PC-FIN")]
    assert rec["classificacao"] == "critico" and rec["status"] == "Falhou"
    assert rec["mensagem"].endswith("Acesso negado") and rec["data_evento"] == "2026-10-06T09:41-03:00"


def zbx_host(nome, disponibilidade="disponivel", monitorado=True):
    return {"nome": nome, "disponibilidade": disponibilidade, "monitorado": monitorado, "status_monitoramento": "Enabled",
            "interfaces_monitoradas": "ZBX", "ultima_atualizacao": None, "ultima_atualizacao_iso": None,
            "origem": "monitoramento"}


def test_zabbix_host_classification():
    _, recs = run(result("zabbix", "zabbix", {"hosts": [
        zbx_host("ok"), zbx_host("down", "indisponivel"), zbx_host("meio", "parcial"),
        zbx_host("off", "desconhecido", monitorado=False), zbx_host("cinza", "desconhecido"),
    ]}))
    cls = {k[1]: r["classificacao"] for k, r in recs.items()}
    assert cls == {"ok": "normal", "down": "indisponivel", "meio": "atencao", "off": "atencao", "cinza": "normal"}
    assert "desconhecida" in recs[("host", "cinza")]["observacoes"][0]


def zbx_problem(desc, sev, status="PROBLEM", situacao="ativo", host="srv-1", origem="ativo"):
    return {"descricao": desc, "severidade": sev, "status": status, "situacao": situacao, "host": host,
            "data_hora": "09:00:00", "data_hora_iso": "2026-10-06T09:00-03:00", "duracao": "3h", "origem": origem}


def test_zabbix_problem_severity_scale_and_classification():
    _, recs = run(result("zabbix", "zabbix", {"problemas": [
        zbx_problem("a", "desastre", host="h1"), zbx_problem("b", "alta", host="h2"),
        zbx_problem("c", "media", host="h3"), zbx_problem("d", "atencao", host="h4"),
        zbx_problem("e", "informacao", host="h5"), zbx_problem("f", "nao_classificada", host="h6"),
        zbx_problem("g", "alta", "RESOLVED", "resolvido", host="h7"),
    ]}))
    by_host = {k[1]: (r["severidade"], r["classificacao"]) for k, r in recs.items()}
    assert by_host == {
        "h1": ("critica", "critico"), "h2": ("alta", "critico"), "h3": ("media", "atencao"), "h4": ("baixa", "atencao"),
        "h5": ("informativa", "normal"), "h6": (None, "atencao"), "h7": ("alta", "normal"),
    }


def test_zabbix_availability_thresholds():
    rows = [{"host": h, "indicador": "Agent", "ok_pct": pct, "problema_pct": None, "abaixo_da_meta": below, "origem": "r"}
            for h, pct, below in (("a", 99.95, False), ("b", 98.0, True), ("c", 90.0, True), ("d", "n/d", None), ("e", 140.0, False))]
    _, recs = run(result("zabbix", "zabbix", {"disponibilidade": rows}))
    cls = {k[1]: r["classificacao"] for k, r in recs.items()}
    assert cls == {"a": "normal", "b": "atencao", "c": "critico", "d": "atencao", "e": "atencao"}
    assert recs[("disponibilidade", "c")]["mensagem"] == "Agent: 90% disponível."
    assert "inválido" in recs[("disponibilidade", "e")]["observacoes"][0]


def test_collection_issues_become_collection_failures():
    issues = [
        {"stage": "autenticacao", "category": "autenticacao", "message": "Acesso negado", "severity": "erro",
         "url": None, "screenshot": "logs/s.png", "timestamp": COLLECTED},
        {"stage": "dispositivos/servidor", "category": "interface_alterada", "message": "Coluna ip ausente",
         "severity": "aviso", "url": None, "screenshot": None, "timestamp": COLLECTED},
    ]
    report, recs = run(result("acronis", "acronis", {}, issues=issues, status="falha"))
    failure = recs[("coleta", "acronis: autenticacao")]
    assert failure["classificacao"] == "falha_coleta" and failure["mensagem"] == "Acesso negado"
    assert failure["observacoes"] == ["Captura de tela: logs/s.png"]
    assert recs[("coleta", "acronis: dispositivos/servidor")]["classificacao"] == "atencao"
    assert report["fontes"][0]["status_coleta"] == "falha" and report["fontes"][0]["falhas_coleta"] == 1


# --- 5.2 limpeza e validação --------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [("  PC  01 ", "PC 01"), ("—", None), ("N/A", None), ("-", None), ("", None), (3, 3)])
def test_clean_value(raw, expected):
    assert clean_value(raw) == expected


def test_required_fields_and_fallbacks():
    report, recs = run(result("sophos", "sophos", {
        "dispositivos": [sophos_device("—"), sophos_device("PC-OK")],
        "alertas": [sophos_alert("Política alterada", "baixa", dispositivo=None)],
    }))
    validation = report["validacao"]
    assert validation["registros_recebidos"] == 3 and validation["registros_consolidados"] == 2
    [discarded] = validation["descartados"]
    assert discarded["categoria"] == "endpoint" and "recurso" in discarded["motivo"]
    platform_alert = recs[("alerta_seguranca", "sophos")]  # sem dispositivo: atribuído à plataforma
    assert "atribuído à própria plataforma" in platform_alert["observacoes"][0]


def test_duplicates_removed_keeping_most_urgent():
    report, recs = run(result("zabbix", "zabbix", {"problemas": [
        zbx_problem("MySQL down", "alta", "RESOLVED", "resolvido", origem="historico_24h"),
        zbx_problem("MySQL down", "alta", origem="ativo"),
    ], "hosts": [zbx_host("srv-1"), {**zbx_host("srv-1"), "origem": "outra"}]}))
    assert report["validacao"]["duplicados_removidos"] == 2
    problem = recs[("problema_monitoramento", "srv-1")]
    assert problem["classificacao"] == "critico" and problem["origem"] == "problemas/ativo"
    assert problem["observacoes"] == ["Também encontrado em: problemas/historico_24h."]


def test_inconsistent_values_are_annotated():
    report, recs = run(result("sophos", "sophos", {"alertas": [
        {**sophos_alert("Sem data", "alta", "PC-1"), "data_hora": "ontem à noite", "data_hora_iso": None},
        sophos_alert("Futuro", "alta", "PC-2", data="2027-01-01T00:00-03:00"),
        sophos_alert("Estranha", "urgentíssima", "PC-3"),
    ]}))
    assert recs[("alerta_seguranca", "PC-1")]["observacoes"] == ["Data não reconhecida: 'ontem à noite'."]
    assert "posterior à data da coleta" in recs[("alerta_seguranca", "PC-2")]["observacoes"][0]
    assert recs[("alerta_seguranca", "PC-3")]["severidade"] is None  # não inventa severidade para alertas
    assert "não reconhecida: 'urgentíssima'" in recs[("alerta_seguranca", "PC-3")]["observacoes"][0]
    assert report["validacao"]["com_observacoes"] == 3


# --- 5.4 consolidação ---------------------------------------------------------------------

def test_records_sorted_by_priority_and_summarized():
    report, _ = run(
        result("zabbix", "zabbix", {"hosts": [zbx_host("ok"), zbx_host("down", "indisponivel")],
                                    "inventario": [{"host": "ok", "grupo": "Linux"}], "extra": [{"x": 1}]}),
        result("sophos", "sophos", {"alertas": [sophos_alert("Malware", "critica"), sophos_alert("RTP", "media", "PC-2")]}),
    )
    order = [(r["classificacao"], r["recurso"]) for r in report["registros"]]
    assert order == [("critico", "PC-1"), ("indisponivel", "down"), ("atencao", "PC-2"), ("normal", "ok")]
    assert [r["prioridade"] for r in report["registros"]] == [1, 1, 3, 4]
    assert report["resumo"] == {
        "total": 4,
        "por_classificacao": {"critico": 1, "indisponivel": 1, "atencao": 1, "normal": 1},
        "por_plataforma": {"zabbix": {"indisponivel": 1, "normal": 1}, "sophos": {"critico": 1, "atencao": 1}},
        "por_categoria": {"host": {"indisponivel": 1, "normal": 1}, "alerta_seguranca": {"critico": 1, "atencao": 1}},
    }
    assert report["validacao"]["conjuntos_ignorados"] == ["zabbix/extra"]  # inventário é auxiliar: não listado


def test_write_outputs_json_and_excel_friendly_csv(tmp_path):
    secret = SecretStr("segredo-no-erro-9")
    report = consolidate([result("acronis", "acronis", {}, issues=[{
        "stage": "x", "category": "inesperado", "message": f"falhou com {secret.reveal()}", "severity": "erro",
        "url": None, "screenshot": None, "timestamp": COLLECTED}])])
    json_path, csv_path = write_outputs(report, tmp_path)
    assert "segredo-no-erro-9" not in json_path.read_text(encoding="utf-8")
    raw = csv_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM: acentos corretos no Excel
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig")), delimiter=";"))
    assert rows[0]["classificacao"] == "falha_coleta" and "segredo-no-erro-9" not in rows[0]["mensagem"]


def test_load_run_and_latest_run(tmp_path):
    old, new = tmp_path / "20261005-080000", tmp_path / "20261006-080000"
    for d in (old, new):
        d.mkdir()
        (d / "zabbix.json").write_text(json.dumps(result("zabbix", "zabbix", {"hosts": [zbx_host("a")]})), encoding="utf-8")
    (new / "consolidado.json").write_text("{}", encoding="utf-8")
    (new / "lixo.json").write_text("[1, 2]", encoding="utf-8")
    assert latest_run_dir(tmp_path) == new
    assert [r["platform"] for r in load_run(new)] == ["zabbix"]
    with pytest.raises(ConfigError, match="jervis collect"):
        latest_run_dir(tmp_path / "vazio")


def test_cli_consolidate_latest_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["-c", "platforms.yaml", "init"]) == 0
    run_dir = tmp_path / "output" / "20261006-080000"
    run_dir.mkdir(parents=True)
    (run_dir / "zabbix.json").write_text(json.dumps(result("zabbix", "zabbix", {
        "hosts": [zbx_host("a"), zbx_host("b", "indisponivel"), {**zbx_host("b"), "origem": "dup"}]})), encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["-c", "platforms.yaml", "consolidate"]) == 0
    out = capsys.readouterr().out
    assert "Consolidado: 2 registro(s) | indisponível: 1 | normal: 1" in out
    assert "1 duplicado(s) removido(s)" in out
    assert (run_dir / "consolidado.json").exists() and (run_dir / "consolidado.csv").exists()

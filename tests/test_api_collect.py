"""Coleta por API de um cliente (Acronis, Zabbix) e relatório geral."""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from jervis.api import ApiError, collect
from jervis.api.run import run_customer
from jervis.config import Settings, AppConfig
from jervis.consolidation import consolidate
from jervis.consolidation.model import ACTIVITY, ATTENTION, CRITICAL, ENDPOINT, MONITORING_PROBLEM, NORMAL, SECURITY_ALERT, UNAVAILABLE
from jervis.db import repository
from jervis.errors import IssueCategory
from jervis.reports.data import executive_summary


def machine(name, status="idle", online=1, backup=False):
    policies = [{"type": "policy.security.antimalware_protection", "last_success_run": "2026-10-01T10:00:00Z"}]
    if backup:
        policies.append({"type": "policy.backup.machine", "last_success_run": "2026-10-07T03:00:00.1234567Z"})
    return {"context": {"id": f"id-{name}", "name": name, "tenant_name": "conta", "attributes": [
                {"name": "agent", "kvs": [{"key": "is_online", "value": online}, {"key": "os_name", "value": "Windows 11"},
                                          {"key": "version", "value": "26.2"}]},
                {"name": "cyberfit", "kvs": [{"key": "cyberfit_score_value", "value": "625"}]}]},
            "aggregate": {"status": status, "names": "Monitoramento;Windows"}, "policies": policies}


ALERTS = [
    {"type": "MachineOffline30", "severity": "critical", "category": "System", "createdAt": "2026-10-08T16:36:00Z",
     "details": {"resourceName": "MNB195", "daysPassed": 149, "errorMessage": {"kbLink": {"serCode": "MachineOffline30"}}}},
    {"type": "EDRIncidentDetected", "severity": "warning", "category": "Detection and response", "createdAt": "2026-10-06T15:06:58Z",
     "details": {"resourceName": "MNB216", "incidentTrigger": "beadpatternlab.com", "isMitigated": "true",
                 "redirectLink": "https://br02-cloud.acronis.com/ui/#/x"}},
    {"type": "NovoTipoQualquer", "severity": "warning", "category": "URL filtering", "createdAt": "2026-10-08T12:49:20Z",
     "details": {"resourceName": "MNB186", "url": "exemplo.site"}},
]
ACTIVITIES = [
    {"type": "Download", "state": "completed", "resource": {"name": "MNB222"}, "startedAt": "2026-10-08T15:29:59.428886469Z",
     "completedAt": "2026-10-08T15:30:00Z", "startedByUser": "BY_SCHEDULE",
     "result": {"code": "error", "error": {"reason": "Acroinst2InstallerDownloadError", "context": {"errMsg": "Reinicie a máquina."}}}},
    {"type": "UpdateVapm", "state": "completed", "resource": {"name": "MNB101"}, "startedAt": "2026-10-08T10:00:00Z",
     "result": {"code": "ok"}},
]


INCIDENTS = [
    {"created_at": "2026-10-06T15:06:58Z", "mitigation_state": "AUTO_MITIGATED", "state": "CLOSED", "host_name": "MNB216",
     "severity": "HIGH", "incident_categories": ["Malware"]},
    {"created_at": "2026-10-02T09:00:00Z", "mitigation_state": "MITIGATED", "state": "CLOSED", "host_name": "MNB118"},
    {"created_at": "2026-09-20T09:00:00Z", "mitigation_state": "AUTO_MITIGATED", "state": "CLOSED", "host_name": "MNB001"},
]
VULNERABILITIES = (
    [{"severity": "critical", "product_name": "Firefox", "vendor": "Mozilla", "cve": f"CVE-2026-{i}", "score": 9 + i / 10,
      "resource_name": f"MNB{i % 3}"} for i in range(5)]
    + [{"severity": "high", "product_name": "Chrome", "cve": "CVE-2026-9", "resource_name": "MNB9"}] * 3
    + [{"severity": None, "product_name": "X", "cve": "CVE-1", "resource_name": "MNB9"}]
)


class FakeAcronis:
    def __init__(self, machines, fail=None):
        self.machine_items, self.fail = machines, fail or {}

    def customer_tenant(self, name):
        if name == "inexistente":
            raise ApiError("[acronis] Cliente 'inexistente' não encontrado no Acronis.")
        return {"id": "t-1", "name": name.upper()}

    def for_customer(self, tenant):
        api = self
        return SimpleNamespace(
            machines=lambda: api._maybe_fail("maquinas", api.machine_items),
            activities=lambda since: api._maybe_fail("atividades", ACTIVITIES),
            # indicadores do painel (API interna do console + incidentes MDR)
            protection_status=lambda: api._maybe_fail("protecao", {"managed": 181, "discovered": 2, "protected": 167, "unprotected": 14}),
            threat_status=lambda: {"auto": 380, "manual": 19, "not_mitigated": 0},
            tactics=lambda since, until: [{"mitre_id": "TA0002", "name": "Execution", "count": 7, "count_prev": 13},
                                          {"mitre_id": "TA0001", "name": "Initial Access", "count": 0, "count_prev": 0}],
            incidents=lambda: INCIDENTS,
            vulnerable_machines=lambda: {"critical": 62, "high": 64, "medium": 2, "low": 1, "none": 22, "protected": 30},
            vulnerabilities=lambda limit=50000: VULNERABILITIES,
            missing_updates=lambda: {"security": 9, "critical": 0, "other": 202},
            patch_installs=lambda since, until: {"maquinas": {"installed": 3, "failed": 2, "reboot_required": 0},
                                                 "atualizacoes": {"installed": 10, "failed": 2}},
            protection_summary=lambda since, until: {"malicious_urls_blocked": 99, "blocked_peripheral_devices": 3,
                                                     "mitigated_threats": 7, "installed_patches": 10},
            remote_sessions=lambda since, until: [{"accessed_by": "ana@cliente.com"}, {"accessed_by": "ana@cliente.com"},
                                                  {"accessed_by": "joao@cliente.com"}])

    def alerts(self, tenant):
        return self._maybe_fail("alertas", ALERTS)

    def _maybe_fail(self, name, value):
        if name in self.fail:
            raise ApiError(self.fail[name], 503)
        return value


# --- conversão das respostas -----------------------------------------------------------


def test_rows_from_acronis_responses():
    row = collect.acronis_machine_row(machine("MNB222", status="error", online=0, backup=True))
    assert row["nome"] == "MNB222" and row["online"] is False and row["tem_backup"] and row["status_label"] == "Erro"
    assert row["ultimo_backup_iso"].startswith("2026-10-07T") and row["ultimo_backup_iso"][-6] in "+-"

    offline, incident, unknown = (collect.acronis_alert_row(a) for a in ALERTS)
    assert offline["titulo"] == "Máquina offline há mais de 30 dias" and offline["detalhe"] == "offline há 149 dias"
    assert incident["mitigado"] is True and incident["detalhe"] == "beadpatternlab.com"
    assert unknown["titulo"] == "Novo tipo qualquer"  # tipo sem tradução: texto legível

    activity = collect.acronis_activity_row(ACTIVITIES[0])
    assert activity["titulo"] == "Download de componentes" and activity["erro"] == "Reinicie a máquina."
    assert activity["resultado_label"] == "Erro"


def test_local_iso():
    assert collect.local_iso(None) is None and collect.local_iso("lixo") == "lixo"
    assert collect.local_iso("2026-10-08T15:29:59.428886469Z").startswith("2026-10-08T")


def test_collect_acronis_and_no_backup_warning():
    result = collect.collect_acronis(FakeAcronis([machine("A"), machine("B", online=0)]), "acronis", "mercos")
    assert result.status == "sucesso" and result.counts() == {"maquinas": 2, "alertas": 3, "atividades": 2}
    assert result.summary["maquinas_sem_backup"] == 2 and result.summary["maquinas_offline"] == 1
    assert any("Nenhuma máquina do cliente tem plano de backup" in i.message for i in result.issues)


def test_collect_acronis_partial_and_missing_customer():
    partial = collect.collect_acronis(FakeAcronis([machine("A", backup=True)], fail={"alertas": "[acronis] fora do ar"}),
                                      "acronis", "mercos")
    assert partial.status == "parcial" and partial.issues[0].category == IssueCategory.UNAVAILABLE
    missing = collect.collect_acronis(FakeAcronis([]), "acronis", "inexistente")
    assert missing.status == "falha" and missing.issues[0].category == IssueCategory.CONFIGURATION


# --- Zabbix ---------------------------------------------------------------------------


class FakeZabbix:
    def __init__(self, groups):
        self.groups, self.calls = groups, []

    def call(self, method, params=None):
        self.calls.append((method, params))
        if method == "hostgroup.get":
            return self.groups if "filter" in params else [{"name": "Clientes/MERCOS"}]
        if method == "host.get":
            return [{"hostid": "1", "host": "srv1", "name": "SRV-01", "status": "0",
                     "interfaces": [{"ip": "10.0.0.1", "port": "10050", "available": "1"}]},
                    {"hostid": "2", "host": "srv2", "name": "SRV-02", "status": "0",
                     "interfaces": [{"ip": "10.0.0.2", "port": "10050", "available": "2"}]},
                    {"hostid": "3", "host": "srv3", "name": "SRV-03", "status": "1", "interfaces": []}]
        if method == "problem.get":
            return [{"objectid": "t1", "name": "Disco cheio", "severity": "4", "clock": "1759939200", "r_eventid": "0",
                     "acknowledged": "0"}]
        if method == "trigger.get":
            return [{"triggerid": "t1", "hosts": [{"name": "SRV-01"}]}]
        if method == "item.get":
            return [{"itemid": "i1", "key_": "icmpping", "hosts": [{"name": "SRV-01"}]},
                    {"itemid": "i2", "key_": "icmpping", "hosts": [{"name": "SRV-02"}]}]
        if method == "trend.get":  # SRV-01: 2 horas cheias e 1 com metade das respostas; SRV-02 sem histórico
            return [{"itemid": "i1", "num": "60", "value_avg": "1"}, {"itemid": "i1", "num": "60", "value_avg": "1"},
                    {"itemid": "i1", "num": "60", "value_avg": "0.5"}]
        if method == "event.get":
            return "42"
        raise AssertionError(method)


def test_collect_zabbix_by_host_group():
    result = collect.collect_zabbix(FakeZabbix([{"groupid": "9", "name": "MERCOS"}]), "zabbix", "MERCOS")
    hosts = {h["nome"]: h for h in result.datasets["hosts"]}
    assert hosts["SRV-01"]["disponibilidade"] == "disponivel" and hosts["SRV-02"]["disponibilidade"] == "indisponivel"
    assert hosts["SRV-03"]["monitorado"] is False
    problem = result.datasets["problemas"][0]
    assert problem == {**problem, "host": "SRV-01", "severidade": "alta", "situacao": "ativo", "descricao": "Disco cheio"}
    assert result.datasets["disponibilidade"] == [{"host": "SRV-01", "indicador": "Disponibilidade (ping)",
                                                   "ok_pct": 83.33, "abaixo_da_meta": True, "amostras": 180}]
    assert result.summary["alarmes_no_periodo"] == 42


def test_collect_zabbix_unknown_group():
    result = collect.collect_zabbix(FakeZabbix([]), "zabbix", "MERCOS")
    assert result.status == "falha" and "Parecidos: Clientes/MERCOS" in result.issues[0].message


# --- classificação e relatório --------------------------------------------------------


def test_classification_and_no_backup_card():
    result = collect.collect_acronis(FakeAcronis([machine("A", status="critical"), machine("B", online=0),
                                                  machine("C", status="warning"), machine("D")]), "acronis", "mercos")
    report = consolidate([result.to_dict()])
    by = {(r["categoria"], r["recurso"]): r for r in report["registros"]}
    assert by[(ENDPOINT, "A")]["classificacao"] == CRITICAL
    assert by[(ENDPOINT, "B")]["classificacao"] == UNAVAILABLE
    assert by[(ENDPOINT, "C")]["classificacao"] == ATTENTION
    assert by[(ENDPOINT, "D")]["classificacao"] == NORMAL
    assert by[(MONITORING_PROBLEM, "MNB195")]["classificacao"] == CRITICAL
    assert by[(SECURITY_ALERT, "MNB216")]["classificacao"] == NORMAL  # incidente mitigado
    assert by[(SECURITY_ALERT, "MNB186")]["classificacao"] == ATTENTION
    assert by[(ACTIVITY, "MNB222")]["classificacao"] == ATTENTION
    assert executive_summary(report)["sem_backup"] == 4


def test_run_customer_with_fake_apis(tmp_path, monkeypatch):
    customer = repository.Customer(1, "MERCOS", "DM-1", services=["acronis", "zabbix"], external={"zabbix": "Clientes/MERCOS"})
    services = [repository.Service(1, "acronis", "https://br02-cloud.acronis.com", "acronis", {}),
                repository.Service(3, "zabbix", "https://noc.example.com", "zabbix", {})]
    monkeypatch.setattr(repository, "find_customer", lambda conn, ref: customer)
    monkeypatch.setattr(repository, "list_services", lambda conn: services)

    def builder(service, store):
        if service.class_identifier == "zabbix":
            raise ApiError("[zabbix] host.get: Invalid params. Not authorized.")
        return FakeAcronis([machine("A", backup=True)])

    config = AppConfig(settings=Settings(output_dir=str(tmp_path), report_formats=["html", "csv"]), platforms={})
    lines = []
    run = run_customer(config, store=None, conn=None, customer_ref="MERCOS", builder=builder, emit=lines.append)
    assert run.run_dir.parent.name == "mercos" and (run.run_dir / "relatorio_mensal.html").exists()
    assert {r.platform: r.status for r in run.results} == {"acronis": "sucesso", "zabbix": "falha"}
    # os três produtos por cliente: relatório mensal, relatório executivo e resumo em Markdown
    assert (run.run_dir / "relatorio_executivo.html").exists() and (run.run_dir / "resumo.md").exists()
    assert (run.run_dir / "metricas.json").exists() and not (run.run_dir / "relatorio_executivo.pdf").exists()
    html = (run.run_dir / "relatorio_mensal.html").read_text(encoding="utf-8")
    assert "Cliente: <b>MERCOS</b>" in html and "MERCOS · Relatório Geral — últimos 30 dias" in html
    assert json.loads((run.run_dir / "cliente.json").read_text(encoding="utf-8"))["servicos"]["zabbix"] == "Clientes/MERCOS"
    assert any("Not authorized" in line for line in lines)


def test_run_customer_without_api_services(monkeypatch):
    monkeypatch.setattr(repository, "find_customer", lambda conn, ref: repository.Customer(2, "Passebus", None))
    monkeypatch.setattr(repository, "list_services", lambda conn: [])
    with pytest.raises(repository.RecordError, match="não está vinculado a Acronis nem Zabbix"):
        run_customer(AppConfig(settings=Settings(), platforms={}), None, None, "Passebus")


def test_stale_or_never_completed_backup_is_critical():
    old = machine("OLD", status="running", backup=True)
    old["policies"][-1]["last_success_run"] = "2025-05-02T12:00:00Z"
    never = machine("NEVER", status="running", backup=True)
    never["policies"][-1]["last_success_run"] = None
    fresh = machine("FRESH", status="running", backup=True)
    fresh["policies"][-1]["last_success_run"] = collect.local_iso("2099-01-01T00:00:00Z")  # data futura: nunca "velho"
    result = collect.collect_acronis(FakeAcronis([old, never, fresh, machine("NOPLAN")]), "acronis", "cliente")
    report = consolidate([result.to_dict()])
    by = {r["recurso"]: r for r in report["registros"] if r["categoria"] == ENDPOINT}
    assert by["OLD"]["classificacao"] == CRITICAL and "Último backup há" in by["OLD"]["mensagem"]
    assert by["NEVER"]["classificacao"] == CRITICAL and "nenhum backup concluído" in by["NEVER"]["mensagem"]
    assert by["FRESH"]["classificacao"] == NORMAL
    summary = executive_summary(report)
    assert summary["sem_backup"] == 1 and summary["backup_desatualizado"] == 2


def test_periods():
    now = datetime(2027, 3, 10, 14, 0).astimezone()
    july = collect.month("2026-07", now=now)
    assert july.label == "Julho de 2026" and july.short == "Julho/2026" and july.monthly
    assert july.contains("2026-07-31T23:59:00-03:00") and not july.contains("2026-08-01T00:00:00-03:00")
    assert collect.month("2026-12", now=now).until.year == 2027
    with pytest.raises(ValueError):
        collect.month("2026-13", now=now)
    assert collect.last_days(7).label == "Últimos 7 dias"


def test_month_defaults_to_current_month_until_now():
    now = datetime(2026, 10, 8, 15, 30).astimezone()
    current = collect.month(now=now)
    assert current.label == "Outubro de 2026 (até 08/10)" and current.short == "Outubro/2026"
    assert current.since == datetime(2026, 10, 1).astimezone() and current.until == now and current.monthly
    with pytest.raises(ValueError, match="ainda não começou"):
        collect.month("2026-11", now=now)  # mês futuro: só quando chegar


def test_acronis_indicators_from_console():
    period = collect.month("2026-10", now=datetime(2026, 10, 8, 15, 30).astimezone())
    result = collect.collect_acronis(FakeAcronis([machine("A")]), "acronis", "c", period)
    ind = result.summary["indicadores"]
    assert ind["protecao"] == {"gerenciados": 181, "descobertos": 2, "protegidos": 167, "desprotegidos": 14}
    assert ind["ameacas"]["total"] == 399 and ind["ameacas"]["nao_mitigadas"] == 0
    assert ind["incidentes_edr"]["total"] == 2 and ind["incidentes_edr"]["maquinas"] == ["MNB118", "MNB216"]  # setembro fica fora
    assert ind["vulnerabilidades"]["total"] == 9 and ind["vulnerabilidades"]["por_severidade"]["critical"] == 5
    assert ind["vulnerabilidades"]["produtos_criticos"][0]["produto"] == "Firefox"
    assert ind["sessoes_remotas"] == {"total": 3, "por_usuario": {"ana@cliente.com": 2, "joao@cliente.com": 1}}
    assert ind["fontes"]["protecao"] == "api_interna" and ind["fontes"]["incidentes_edr"] == "api_publica"


def test_acronis_indicator_failure_is_a_warning_not_a_guess():
    result = collect.collect_acronis(FakeAcronis([machine("A")], fail={"protecao": "[acronis] HTTP 404"}), "acronis", "c")
    assert "protecao" not in result.summary["indicadores"] and "ameacas" in result.summary["indicadores"]
    assert any("API interna do console" in i.message for i in result.issues)


def test_acronis_period_filters_alerts_and_activities():
    period = collect.month("2026-10")
    result = collect.collect_acronis(FakeAcronis([machine("A")]), "acronis", "c", period)
    assert len(result.datasets["alertas"]) == 3 and len(result.datasets["atividades"]) == 2
    september = collect.collect_acronis(FakeAcronis([machine("A")]), "acronis", "c", collect.month("2026-09"))
    assert september.datasets["alertas"] == [] and september.datasets["atividades"] == []
    assert len(september.datasets["maquinas"]) == 1  # máquinas: situação atual, não filtrada por período

"""Sophos Central por API: cliente (token, whoami, tenants, paginação), coleta, indicadores e documentos."""

import io
from types import SimpleNamespace
import urllib.error
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from jervis.api import ApiError, collect, credentials as api_credentials
from jervis.api.sophos import SophosApi
from jervis.consolidation import consolidate
from jervis.reports import executive, metrics, summary_md

from test_api import FakeApi, secret

NOW = datetime(2026, 10, 9, 10, 0).astimezone()
REGION = "https://api-us01.central.sophos.com"


def endpoint(name, overall="good", threats="good", services="good", kind="computer", tamper=True, last="2026-10-09T09:00:00Z"):
    return {"hostname": name, "type": kind, "health": {"overall": overall, "threats": {"status": threats}, "services": {"status": services}},
            "os": {"name": "Windows 11 Pro", "platform": "windows", "isServer": kind == "server"}, "ipv4Addresses": ["10.0.0.5"],
            "associatedPerson": {"viaLogin": "CORP\\ana"}, "lastSeenAt": last, "group": {"name": "Financeiro"},
            "tamperProtectionEnabled": tamper, "assignedProducts": [{"code": "endpointProtection", "version": "2026.2"}]}


ENDPOINTS = [endpoint("PC-01"), endpoint("PC-02", overall="bad", threats="bad"), endpoint("SRV-01", kind="server", tamper=False),
             endpoint("PC-03", overall="suspicious", services="bad"), endpoint("PC-OLD", last="2026-08-01T09:00:00Z")]
ALERTS = [{"id": "a1", "category": "malware", "description": "Malware detectado: Troj/Agent-X", "type": "Event::Endpoint::Threat",
           "severity": "high", "raisedAt": "2026-10-05T13:00:00Z", "managedAgent": {"id": "e2", "type": "computer", "name": "PC-02"},
           "product": "endpoint"},
          {"id": "a2", "category": "updating", "description": "Falha na atualização", "type": "Event::Endpoint::UpdateFailure",
           "severity": "medium", "raisedAt": "2026-10-06T13:00:00Z", "managedAgent": {"id": "e3", "type": "server", "name": "SRV-01"},
           "product": "server"}]


def routes(tokens, kind="partner"):
    def token(req):
        tokens.append(req)
        return {"access_token": "jwt-1", "expires_in": 3600, "token_type": "bearer"}

    def tenants(req):
        page = parse_qs(urlsplit(req["url"]).query).get("page", ["1"])[0]
        items = {"1": [{"id": "t1", "name": "AUXILIUM CORRETORA", "apiHost": REGION, "dataRegion": "us01"}],
                 "2": [{"id": "t2", "name": "Outro Cliente", "apiHost": REGION}]}[page]
        return {"items": items, "pages": {"current": int(page), "size": 1, "total": 2, "maxSize": 100}}

    def endpoints(req):
        key = parse_qs(urlsplit(req["url"]).query).get("pageFromKey", [None])[0]
        if key is None:
            return {"items": ENDPOINTS[:3], "pages": {"nextKey": "k2", "size": 3, "maxSize": 500}}
        return {"items": ENDPOINTS[3:], "pages": {"size": 2, "maxSize": 500}}

    return {
        ("POST", "/api/v2/oauth2/token"): token,
        ("GET", "/whoami/v1"): {"id": "partner-9", "idType": kind,
                                "apiHosts": {"global": "https://api.central.sophos.com", "dataRegion": REGION}},
        ("GET", "/partner/v1/tenants"): tenants,
        ("GET", "/endpoint/v1/endpoints"): endpoints,
        ("GET", "/common/v1/alerts"): {"items": ALERTS, "pages": {"size": 2, "maxSize": 100}},
    }


def api(tokens=None, kind="partner"):
    fake = FakeApi(routes([] if tokens is None else tokens, kind))
    return SophosApi("https://api.central.sophos.com", secret("cid"), secret("s3cr3t"), opener=fake), fake


def test_token_whoami_and_partner_tenants():
    tokens = []
    sophos, fake = api(tokens)
    assert sophos.check() == "conta 'partner' (partner-9); 2 cliente(s) (tenants)"
    assert sophos.customer_names() == ["AUXILIUM CORRETORA", "Outro Cliente"]
    assert len(tokens) == 1  # token reaproveitado
    assert parse_qs(tokens[0]["body"]) == {"grant_type": ["client_credentials"], "client_id": ["cid"],
                                           "client_secret": ["s3cr3t"], "scope": ["token"]}
    listing = [r for r in fake.requests if r["path"].endswith("/partner/v1/tenants")]
    assert listing[0]["headers"]["x-partner-id"] == "partner-9" and "pageTotal=true" in listing[0]["url"]
    assert "pageTotal" not in listing[1]["url"]  # só na primeira página
    assert listing[0]["headers"]["authorization"] == "Bearer jwt-1"


def test_customer_tenant_not_found_suggests_similar():
    sophos, _ = api()
    with pytest.raises(ApiError, match="Parecidos: AUXILIUM CORRETORA"):
        sophos.customer_tenant("Auxilium")


def test_rejected_credential_does_not_leak_the_secret():
    fake = FakeApi({("POST", "/api/v2/oauth2/token"): urllib.error.HTTPError(
        "u", 401, "Unauthorized", {}, io.BytesIO(b'{"errorCode": "oauth.invalid_client_secret", "message": "Invalid client secret"}'))})
    sophos = SophosApi("https://api.central.sophos.com", secret("cid"), secret("errado"), opener=fake)
    with pytest.raises(ApiError, match="HTTP 401 – Invalid client secret") as info:
        sophos.check()
    assert "errado" not in str(info.value)


def test_collect_endpoints_and_alerts_of_the_tenant():
    sophos, fake = api()
    period = collect.month("2026-10", now=NOW)
    result = collect.collect_sophos(sophos, "sophos", "auxilium corretora", period)
    assert result.status == "sucesso" and result.summary["cliente_na_plataforma"] == "AUXILIUM CORRETORA"
    devices = result.datasets["dispositivos"]
    assert [d["nome"] for d in devices] == ["PC-01", "PC-02", "SRV-01", "PC-03", "PC-OLD"]  # duas páginas
    assert devices[1]["status_agente"] == "Ruim" and devices[1]["situacao_protecao"] == "Ameaças: Ruim; Serviços: Bom"
    assert devices[2]["tipo"] == "Servidor" and devices[2]["protecao_adulteracao"] is False
    data_calls = [r for r in fake.requests if r["path"].startswith(REGION)]
    assert all(r["headers"]["x-tenant-id"] == "t1" for r in data_calls)
    alerts_call = next(r for r in data_calls if r["path"].endswith("/common/v1/alerts"))
    query = parse_qs(urlsplit(alerts_call["url"]).query)
    assert query["from"][0].startswith("2026-10-01T03:00:00") and query["from"][0].endswith("Z")
    assert result.datasets["alertas"][0]["severidade"] == "alta" and result.datasets["alertas"][0]["dispositivo"] == "PC-02"


def compute():
    sophos, _ = api()
    period = collect.month("2026-10", now=NOW)
    data = [collect.collect_sophos(sophos, "sophos", "AUXILIUM CORRETORA", period).to_dict()]
    meta = {"cliente": "AUXILIUM CORRETORA", "periodo": period.label, "periodo_curto": period.short, "competencia": "2026-10", "parcial": True}
    return metrics.compute(data, consolidate(data), meta)


def test_sophos_metrics_and_recommendations():
    m = compute()
    s = metrics.first(m, "sophos")
    assert s["endpoints"] == {"total": 5, "computadores": 4, "servidores": 1}
    assert s["saude"] == {"boa": 3, "suspeita": 1, "ruim": 1, "desconhecida": 0}
    assert s["ameacas_ativas"] == {"quantidade": 1, "maquinas": ["PC-02"]}
    assert s["servicos_com_falha"]["maquinas"] == ["PC-03"] and s["adulteracao_desativada"]["maquinas"] == ["SRV-01"]
    assert s["sem_comunicacao"]["maquinas"] == ["PC-OLD"]
    assert s["alertas"]["por_severidade"] == {"alta": 1, "media": 1, "baixa": 0}
    keys = {r["chave"]: r["criticidade"] for r in m["recomendacoes"]}
    assert keys == {"sophos_ameacas": "alta", "sophos_servicos": "alta", "sophos_alertas_altos": "alta",
                    "sophos_adulteracao": "media", "sophos_sem_comunicacao": "media"}


def test_sophos_in_summary_and_executive():
    m = compute()
    md = summary_md.render(m, [], [])
    assert "## Sophos Central" in md and "Endpoints com ameaça ativa: 1 (PC-02)" in md
    assert "O Sophos Central protege 5 endpoints" in md
    doc = executive.build(m, [], [], company="Contego Security", issued=NOW)
    assert "Sophos Central — Proteção de Endpoints" in [p["titulo"] for p in doc["paineis"]]
    assert "No Sophos Central são 5 endpoints gerenciados" in doc["sumario"][0]
    assert any(p["titulo"] == "Ameaças ativas em endpoints (Sophos)" for p in doc["pontos"])


def test_sophos_api_credentials_fields(memory_keyring):
    from jervis.credentials import CredentialStore
    store = CredentialStore()
    api_credentials.save(store, "sophos", "sophos", {"client_id": "cid", "client_secret": "sec"})
    loaded = api_credentials.load(store, "sophos", "sophos", environ={})
    assert loaded["client_id"].reveal() == "cid" and loaded["client_secret"].reveal() == "sec"


def test_customer_report_with_sophos(tmp_path, monkeypatch):
    from jervis.api.run import run_customer
    from jervis.config import AppConfig, Settings
    from jervis.db import repository

    customer = repository.Customer(7, "AUXILIUM CORRETORA", None, services=["sophos"])
    monkeypatch.setattr(repository, "find_customer", lambda conn, ref: customer)
    monkeypatch.setattr(repository, "list_services", lambda conn: [
        repository.Service(6, "sophos", "https://api.central.sophos.com", "sophos", {})])
    config = AppConfig(settings=Settings(output_dir=str(tmp_path), report_formats=["html", "csv"]), platforms={})
    run = run_customer(config, None, None, "AUXILIUM CORRETORA", period=collect.month("2026-10", now=NOW),
                       builder=lambda service, store: api()[0], emit=lambda line: None)
    assert {r.platform: r.status for r in run.results} == {"sophos": "sucesso"}
    folder = run.run_dir
    assert folder.parent.name == "auxilium_corretora"
    assert "Sophos Central" in (folder / "relatorio_mensal.html").read_text(encoding="utf-8")
    assert "Sophos Central — Proteção de Endpoints" in (folder / "relatorio_executivo.html").read_text(encoding="utf-8")
    assert "## Sophos Central" in (folder / "resumo.md").read_text(encoding="utf-8")


# --- casos vistos na conta real ----------------------------------------------------------


def test_duplicate_tenant_names_need_the_tenant_id():
    sophos, _ = api()
    twins = [{"id": "aaaa-1", "name": "Unimed Planalto Norte", "apiHost": REGION, "dataRegion": "br01", "billingType": "usage",
              "products": [{"code": "NDR-MSP"}], "showAs": "Unimed Planalto Norte"},
             {"id": "bbbb-2", "name": "Unimed Planalto Norte", "apiHost": REGION, "dataRegion": "us01", "billingType": "term",
              "products": [], "showAs": "Unimed Planalto Norte (antigo)"}]
    sophos.tenants = lambda: twins
    with pytest.raises(ApiError, match=r"aaaa-1 \(região br01, faturamento usage, 1 produto\(s\)\); bbbb-2"):
        sophos.customer_tenant("Unimed Planalto Norte")
    assert sophos.customer_tenant("bbbb-2")["dataRegion"] == "us01"  # pelo id do tenant
    assert sophos.customer_tenant("unimed planalto norte (antigo)")["id"] == "bbbb-2"  # pelo "showAs"
    assert sophos.customer_aliases()["aaaa-1"] == "Unimed Planalto Norte"


def test_link_by_tenant_id_counts_as_linked():
    from jervis.api import sync
    from jervis.db.repository import Customer

    people = [Customer(24, "UNIMED PLANALTO NORTE", None, services=["sophos"], external={"sophos": "aaaa-1"})]
    rows = sync.compare(["Unimed Planalto Norte"], people, "sophos", {"aaaa-1": "Unimed Planalto Norte"})
    assert rows[0].status == sync.LINKED and rows[0].customer.id == 24  # e não "não cadastrado" (que duplicaria no import)
    assert sync.orphans(["Unimed Planalto Norte"], people, "sophos", {"aaaa-1": "Unimed Planalto Norte"}) == []


def test_firewall_only_tenant():
    from jervis.api.sophos import SophosApi as _Api
    firewall_alert = {"id": "f1", "category": "connectivity", "description": "IPSec Connection terminated", "severity": "medium",
                      "type": "Event::Firewall::Connectivity", "raisedAt": "2026-10-05T13:00:00Z", "status": "open",
                      "managedAgent": {"id": "fw", "type": "utm", "name": "X11509922DT2707"}, "product": "firewall"}
    routes_fw = routes([])
    routes_fw[("GET", "/endpoint/v1/endpoints")] = {"items": [], "pages": {"size": 50, "total": 0, "items": 0, "maxSize": 500}}
    routes_fw[("GET", "/common/v1/alerts")] = {"items": [firewall_alert], "pages": {"size": 1, "maxSize": 100}}
    sophos = _Api("https://api.central.sophos.com", secret("cid"), secret("s3cr3t"), opener=FakeApi(routes_fw))
    period = collect.month("2026-10", now=NOW)
    data = [collect.collect_sophos(sophos, "sophos", "AUXILIUM CORRETORA", period).to_dict()]
    assert data[0]["datasets"]["alertas"][0]["produto"] == "Firewall" and data[0]["datasets"]["alertas"][0]["situacao"] == "Aberto"
    m = metrics.compute(data, consolidate(data), {"cliente": "AUXILIUM CORRETORA", "periodo": period.label, "periodo_curto": period.short})
    s = metrics.first(m, "sophos")
    assert s["endpoints"]["total"] == 0 and s["alertas"]["por_produto"] == {"Firewall": 1}
    md = summary_md.render(m, [], [])
    assert "Endpoints gerenciados: 0 (nenhum computador ou servidor" in md and "Alertas por origem: Firewall: 1" in md
    assert "Endpoints com ameaça ativa" not in md
    doc = executive.build(m, [], [], company="Contego Security", issued=NOW)
    assert [p["titulo"] for p in doc["paineis"]] == ["Sophos Central"]
    assert "não há endpoints deste cliente na plataforma" in doc["sumario"][0] and "segurança de rede" in doc["sumario"][0]
    assert "nenhum endpoint do Sophos Central apresenta ameaça ativa" not in doc["consideracoes"]


def test_endpoints_with_the_same_name_are_kept_apart():
    old, new = endpoint("FAT-02", last="2026-07-21T14:31:18Z"), endpoint("FAT-02")
    old["id"], new["id"] = "id-antigo", "id-novo"
    period = collect.month("2026-10", now=NOW)
    result = collect.collect_sophos(SimpleNamespace(customer_tenant=lambda name: {"id": "t1", "name": name, "apiHost": REGION},
                                                    endpoints=lambda t: [old, new], alerts=lambda t, a, b: []),
                                    "sophos", "AUXILIUM CORRETORA", period)
    data = [result.to_dict()]
    consolidated = consolidate(data)
    assert consolidated["validacao"]["duplicados_removidos"] == 0  # dois registros (ids diferentes), não um duplicado
    m = metrics.compute(data, consolidated, {"cliente": "X", "periodo": period.label, "periodo_curto": period.short})
    s = metrics.first(m, "sophos")
    assert s["nomes_repetidos"] == {"quantidade": 1, "maquinas": ["FAT-02"]} and s["sem_comunicacao"]["maquinas"] == ["FAT-02"]
    assert {r["chave"]: r["criticidade"] for r in m["recomendacoes"]}["sophos_registros_repetidos"] == "baixa"


def test_suspicious_item_is_not_reported_as_an_active_threat():
    pua = endpoint("QEE-04", overall="suspicious", threats="suspicious")
    period = collect.month("2026-10", now=NOW)
    result = collect.collect_sophos(SimpleNamespace(customer_tenant=lambda name: {"id": "t1", "name": name, "apiHost": REGION},
                                                    endpoints=lambda t: [pua, endpoint("QEE-05")], alerts=lambda t, a, b: []),
                                    "sophos", "CERMISSOES", period)
    data = [result.to_dict()]
    m = metrics.compute(data, consolidate(data), {"cliente": "CERMISSOES", "periodo": period.label, "periodo_curto": period.short})
    s = metrics.first(m, "sophos")
    assert s["ameacas_ativas"]["quantidade"] == 0 and s["itens_suspeitos"] == {"quantidade": 1, "maquinas": ["QEE-04"]}
    assert {r["chave"]: r["criticidade"] for r in m["recomendacoes"]} == {"sophos_suspeitos": "media"}
    assert "nenhum com ameaça ativa e 1 com item suspeito pendente." in executive.build(m, [], [], issued=NOW)["sumario"][0]


def test_alert_description_drops_control_characters():
    row = collect.sophos_alert_row({"description": "botnet null\x00\x13 digicert\x01 ", "severity": "high"})
    assert row["descricao"] == "botnet null digicert" and row["tipo"] == "botnet null digicert"

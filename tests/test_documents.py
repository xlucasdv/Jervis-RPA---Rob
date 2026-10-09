"""Produtos por cliente além do relatório mensal: indicadores (metricas.json), resumo em Markdown e relatório
executivo — incluindo a evolução contra o mês anterior e a conferência dos números do texto da IA."""

from datetime import datetime

import pytest

from jervis.api import collect
from jervis.consolidation import consolidate
from jervis.reports import ai, executive, metrics, summary_md
from jervis.reports.html import render_executive

from test_api_collect import FakeAcronis, machine

NOW = datetime(2026, 10, 8, 15, 30).astimezone()


def compute(fake=None, period=None):
    period = period or collect.month("2026-10", now=NOW)
    result = collect.collect_acronis(fake or FakeAcronis([machine("A"), machine("B", online=0)]), "acronis", "mercos", period)
    data = [result.to_dict()]
    meta = {"cliente": "MERCOS", "periodo": period.label, "periodo_curto": period.short, "competencia": f"{period.since:%Y-%m}",
            "parcial": period.until.day != 1, "contrato": {"acronis": {"produtos": ["Acronis EDR"], "dispositivos": 169}}}
    return metrics.compute(data, consolidate(data), meta)


def test_metrics_and_recommendations():
    m = compute()
    a = metrics.first(m, "acronis")
    assert a["inventario"]["desprotegidos"] == 14 and a["vulnerabilidades"]["total"] == 9
    keys = {r["chave"]: r["criticidade"] for r in m["recomendacoes"]}
    assert keys["desprotegidos"] == "alta" and keys["patches"] == "alta"
    assert m["parcial"] is True and m["competencia"] == "2026-10"


def test_previous_month_evolution_and_follow_up(tmp_path):
    september, october = tmp_path / "20261001-090000", tmp_path / "20261008-153000"
    september.mkdir(), october.mkdir()
    before = compute()
    before.update(competencia="2026-09", parcial=False, periodo_curto="Setembro/2026")
    metrics.first(before, "acronis")["inventario"]["desprotegidos"] = 20
    metrics.save(before, september)
    current = compute()
    metrics.save(current, october)

    previous = metrics.previous(october)
    assert previous["competencia"] == "2026-09"
    rows = {r["indicador"]: r for r in metrics.evolution(current, previous)}
    assert rows["Endpoints desprotegidos"]["leitura"] == "melhora"
    assert "Incidentes EDR" not in rows  # mês atual incompleto: totais acumulados não são comparados
    follow = {f["recomendacao"]: f for f in metrics.follow_up(current, previous)}
    assert all(f["status"] == "Pendente" for f in follow.values())
    assert not any("bloqueio(s) de URLs" in k for k in follow)  # temas informativos ficam fora


def test_summary_md_follows_the_template():
    m = compute()
    md = summary_md.render(m, [], [])
    assert md.startswith("# Resumo MSR – MERCOS – Outubro/2026")
    for section in ("## Contexto do Ambiente", "## Endpoint Security & EDR (Acronis)", "## Insumo para a IA"):
        assert section in md
    assert "Não inventar dados" in md and "Dispositivos Gerenciados: 181" in md


def test_executive_document(tmp_path):
    m = compute()
    doc = executive.build(m, [], [], company="Contego Security", issued=NOW)
    assert doc["emitido"] == "8 de outubro de 2026" and doc["competencia"] == "Outubro de 2026 (até 08/10)"
    titles = [p["titulo"] for p in doc["paineis"]]
    assert titles[:2] == ["Endpoint Security — Inventário e Estado de Proteção", "EDR — Ameaças, Incidentes e Controles"]
    html = render_executive(doc)
    assert "Sumário Executivo" in html and "Recomendações Priorizadas" in html and "MERCOS" in html
    assert "primeiro relatório deste cliente" in html  # sem mês anterior: linha de base
    assert ". e permanece" not in doc["consideracoes"]


# --- IA: só números presentes nos dados -------------------------------------------------------


def test_ai_number_check():
    source = "Vulnerabilidades: 7.295 | Disponibilidade 99,5% | 14 desprotegidos"
    assert ai.numbers(source) == {"7295", "99.5", "14"}
    ok = {"sumario": ["São 7.295 vulnerabilidades e 14 endpoints desprotegidos."], "pontos": [],
          "consideracoes": "Disponibilidade de 99,5%."}
    ai.check_numbers(ok, source)
    invented = dict(ok, consideracoes="Cerca de 57% do total.")
    with pytest.raises(ai.AiError, match="57"):
        ai.check_numbers(invented, source)


def test_ai_failure_falls_back_to_template(tmp_path, monkeypatch):
    from jervis.api.run import write_customer_documents
    from jervis.config import Settings

    def fail(md, store, settings):
        raise ai.AiError("sem conexão com a API do Claude")

    monkeypatch.setattr(ai, "write_executive", fail)
    period = collect.month("2026-10", now=NOW)
    result = collect.collect_acronis(FakeAcronis([machine("A")]), "acronis", "mercos", period)
    data = [result.to_dict()]
    lines = []
    files = write_customer_documents(data, consolidate(data), {"cliente": "MERCOS", "periodo": period.label,
                                                              "periodo_curto": period.short, "competencia": "2026-10"},
                                     tmp_path, Settings(), lines.append, ai=True, pdf=False)
    assert files["md"][0].name == "resumo.md" and files["executivo"][0].name == "relatorio_executivo.html"
    assert any("texto da IA não usado" in line for line in lines)
    assert "Gerado automaticamente" in files["executivo"][0].read_text(encoding="utf-8")

"""Relatório no padrão de apresentação: gráficos, notas da equipe e montagem das páginas."""

from jervis.api import collect
from jervis.consolidation import consolidate
from jervis.reports.data import build_report_data
from jervis.reports.html import render_slides
from jervis.reports.slides import bars, build_slides, donut, load_notes

from test_api_collect import FakeAcronis, machine


def report():
    result = collect.collect_acronis(FakeAcronis([machine("A", status="critical"), machine("B", online=0), machine("C")]),
                                     "acronis", "Cliente", collect.month("2026-10"))
    return consolidate([result.to_dict()])


def slides(meta=None):
    consolidated = report()
    return build_slides(build_report_data(consolidated, "T"), consolidated, meta)


def test_donut_and_bars():
    svg = donut([("A", 3, "#111"), ("B", 1, "#222"), ("C", 0, "#333")])
    assert svg.count("<circle") == 2 and ">3<" in svg and ">1<" in svg  # fatia zerada não é desenhada
    assert "Sem dados" in donut([("A", 0, "#111")])
    html = bars([("<host>", 50.0, "50%"), ("b", 100.0, "100%")], "#4f8ff7", 100)
    assert "&lt;host&gt;" in html and "width:50.0%" in html


def test_pages_without_team_notes():
    s = slides({"cliente": "Cliente X", "tipo": "Relatório Mensal", "periodo": "Outubro de 2026", "periodo_curto": "Outubro/2026"})
    kinds = [p["kind"] for p in s["slides"]]
    assert kinds[0] == "cover" and kinds[1] == "cards" and "service" in kinds and "recommendations" in kinds
    assert s["slides"][1]["title"] == "Principais Achados do Período"  # sem notas: achados derivados dos dados
    assert s["footer"] == "Cliente X · Relatório Mensal — Outubro/2026"
    assert [p["number"] for p in s["slides"]][:3] == ["01", "02", "03"]
    service = next(p for p in s["slides"] if p["kind"] == "service")
    assert [k["label"] for k in service["kpis"]] == ["Máquinas monitoradas", "Sem backup em dia", "Alertas no período",
                                                      "Atividades com erro"]
    assert service["kpis"][1]["value"] == "3"  # nenhuma máquina com backup


def test_team_notes_are_included(tmp_path):
    notes_file = tmp_path / "2026-10.yaml"
    notes_file.write_text("""
destaques:
  - {titulo: Atualização crítica do agente, texto: Concluída em todas as máquinas., icone: shield}
notas:
  - {titulo: Nota técnica — Firmware, selo: DECISÃO TÉCNICA · NÃO É PENDÊNCIA, texto: Mantida a versão estável., proxima_acao: Reavaliar no próximo mês.}
melhorias:
  - {titulo: Novos dashboards, texto: Em criação no SIEM.}
recomendacoes:
  - {criticidade: decisão técnica, ponto: Não aplicar o firmware 22.0.1., acao: Manter 21.5.2.}
observacoes:
  acronis: [Cliente pediu revisão dos planos.]
""", encoding="utf-8")
    s = slides({"cliente": "C", "tipo": "Relatório Mensal", "periodo": "Outubro de 2026", "periodo_curto": "Outubro/2026",
                "notas": load_notes(notes_file)})
    titles = [p.get("title") for p in s["slides"]]
    assert "Destaques do Mês — Principais Entregas" in titles and "Nota técnica — Firmware" in titles
    assert "Melhorias em Andamento" in titles
    recs = next(p for p in s["slides"] if p["kind"] == "recommendations")["recs"]
    assert recs[0]["label"] == "Decisão técnica" and recs[0]["point"] == "Não aplicar o firmware 22.0.1."
    assert [r["label"] for r in recs] == sorted([r["label"] for r in recs], key=["Decisão técnica", "Alta", "Média", "Baixa"].index)
    service = next(p for p in s["slides"] if p["kind"] == "service")
    assert ("blue", "Cliente pediu revisão dos planos.") in service["bullets"]
    html = render_slides(s)
    assert "DECISÃO TÉCNICA · NÃO É PENDÊNCIA" in html and "Próxima ação: Reavaliar no próximo mês." in html


def test_missing_or_empty_notes():
    assert load_notes(None) == {}


def test_logo_embedded_in_report(tmp_path):
    from jervis.reports.slides import logo_data_uri
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 20)
    uri = logo_data_uri(str(logo))
    assert uri.startswith("data:image/png;base64,")
    assert logo_data_uri(str(tmp_path / "nao_existe.png")) == "" and logo_data_uri("") == ""
    consolidated = report()
    s = build_slides(build_report_data(consolidated, "T"), consolidated, None, "Contego Security", uri)
    html = render_slides(s)
    assert html.count(uri) >= len(s["slides"])  # capa + rodapé de cada página

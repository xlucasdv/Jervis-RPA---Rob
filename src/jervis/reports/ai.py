"""Redação opcional (``--ia``) do texto do relatório executivo pela API do Claude.

A IA recebe apenas o ``resumo.md`` (indicadores já calculados) e devolve o sumário executivo, os pontos de
atenção e as considerações finais. Os painéis, recomendações, evolução e acompanhamento continuam vindo dos
dados. Para não publicar dados inventados, o texto só é aceito se todo número citado existir no resumo;
caso contrário levanta ``AiError`` e o relatório sai com o texto padrão.

Chave da API: cofre do Windows (``jervis ia set-key``) ou a variável/perfil padrão do SDK (ANTHROPIC_API_KEY).
"""

from __future__ import annotations

import json
import re
from typing import Any

from jervis.credentials import CredentialError

MODEL = "claude-opus-5-5"
API_KEY_SECRET = "anthropic_api_key"

SYSTEM = """Você é analista sênior de um provedor de serviços gerenciados de segurança (MSSP) e redige relatórios \
executivos mensais para a diretoria dos clientes, em português do Brasil.

Regras obrigatórias:
- Use somente os fatos e números do resumo fornecido. Não invente, não estime e não calcule números novos \
(nem percentuais, somas ou diferenças que não estejam escritos no resumo).
- Indicadores marcados como "não coletado" não podem ser citados como números.
- Escreva números exatamente como aparecem no resumo (ex.: 7.295).
- Linguagem executiva, clara e profissional; explique termos técnicos em poucas palavras quando usá-los.
- Não repita as tabelas: o documento já traz painel de indicadores, recomendações, evolução e acompanhamento.
- Não use listas numeradas, marcadores nem Markdown dentro dos textos."""

SCHEMA = {
    "type": "object",
    "properties": {
        "sumario": {"type": "array", "items": {"type": "string"},
                    "description": "3 a 4 parágrafos do Sumário Executivo"},
        "pontos": {"type": "array", "description": "Pontos de atenção, do mais grave ao menos grave",
                   "items": {"type": "object",
                             "properties": {"titulo": {"type": "string"},
                                            "texto": {"type": "string", "description": "contexto de risco do ponto"}},
                             "required": ["titulo", "texto"], "additionalProperties": False}},
        "consideracoes": {"type": "string", "description": "um parágrafo de Considerações Finais"},
    },
    "required": ["sumario", "pontos", "consideracoes"],
    "additionalProperties": False,
}

# número com separador de milhar (7.295), decimal (99,5) ou simples (38)
_NUMBER = re.compile(r"\d+(?:[.,]\d+)*")


class AiError(Exception):
    """Texto da IA indisponível ou rejeitado; o relatório usa o texto padrão."""


def numbers(text: str) -> set[str]:
    """Números do texto normalizados: '7.295' -> '7295', '99,5' -> '99.5'."""
    out = set()
    for raw in _NUMBER.findall(text):
        if re.fullmatch(r"\d{1,3}(?:\.\d{3})+", raw):
            out.add(raw.replace(".", ""))
        else:
            out.add(raw.replace(",", "."))
    return out


def check_numbers(texts: dict[str, Any], source: str) -> None:
    """Levanta AiError se o texto citar número que não está no resumo."""
    written = " ".join(texts["sumario"] + [p["titulo"] + " " + p["texto"] for p in texts["pontos"]] + [texts["consideracoes"]])
    unknown = sorted(numbers(written) - numbers(source), key=lambda v: (len(v), v))
    if unknown:
        raise AiError(f"a IA citou números que não estão nos dados: {', '.join(unknown[:8])}")


def _client(store):
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - dependência declarada no pyproject
        raise AiError("pacote 'anthropic' não instalado") from exc
    key = None
    if store is not None:
        try:
            key = store.get_secret(API_KEY_SECRET)
        except CredentialError:
            key = None
    # sem chave no cofre, o SDK procura ANTHROPIC_API_KEY ou o perfil do `ant auth login`
    return anthropic, (anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic())


def write_executive(md_text: str, store=None, settings=None) -> dict[str, Any]:
    """{sumario: [str], pontos: [{titulo, texto}], consideracoes: str} redigidos a partir do resumo."""
    anthropic, client = _client(store)
    try:
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=SYSTEM,
            messages=[{"role": "user", "content": "Resumo mensal do cliente (fonte única de dados):\n\n" + md_text
                       + "\n\nRedija o sumário executivo, os pontos de atenção com contexto de risco e as considerações finais."}],
            output_config={"effort": "high", "format": {"type": "json_schema", "schema": SCHEMA}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.AuthenticationError as exc:
        raise AiError("chave da API do Claude inválida (jervis ia set-key)") from exc
    except anthropic.RateLimitError as exc:
        raise AiError("limite de uso da API do Claude atingido; tente mais tarde") from exc
    except anthropic.APIStatusError as exc:
        raise AiError(f"API do Claude respondeu HTTP {exc.status_code}") from exc
    except anthropic.APIConnectionError as exc:
        raise AiError("sem conexão com a API do Claude") from exc
    except anthropic.AnthropicError as exc:  # ex.: nenhuma credencial configurada
        raise AiError(str(exc).splitlines()[0]) from exc

    if response.stop_reason == "refusal":
        raise AiError("a IA recusou a solicitação")
    if response.stop_reason == "max_tokens":
        raise AiError("resposta da IA incompleta")
    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        texts = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AiError("resposta da IA fora do formato esperado") from exc
    if not texts.get("sumario") or not texts.get("consideracoes"):
        raise AiError("resposta da IA sem sumário ou considerações")
    check_numbers(texts, md_text)
    return texts

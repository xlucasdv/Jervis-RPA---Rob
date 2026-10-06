"""Saúde da própria ferramenta (Feature 9.5).

Resume, a partir do histórico, se a ferramenta está cumprindo seu papel:

  ok       — última execução bem-sucedida e todas as plataformas ativas coletadas recentemente;
  atencao  — última execução parcial, com avisos, relatório que falhou ou execução interrompida;
  critico  — última execução falhou, nenhuma execução registrada, ou alguma plataforma ativa
             está há mais de ``max_hours_without_success`` horas sem coleta bem-sucedida.

O resultado é gravado em ``output/status.json`` ao fim de cada execução e exibido por
``jervis status`` (código de saída 0/2/3), para ser lido por um monitoramento externo — por
exemplo, o próprio Zabbix.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jervis.collectors import COLLECTORS
from jervis.collectors.models import now_iso
from jervis.config import AppConfig
from jervis.fileutil import atomic_write_text

STATUS_FILE = "status.json"
HEALTH_EXIT = {"ok": 0, "atencao": 2, "critico": 3}


def _parse(iso: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(iso) if iso else None
    except ValueError:
        return None


def compute_health(config: AppConfig, now: datetime | None = None) -> dict[str, Any]:
    from jervis.runner import is_running, read_history, running_manifests  # evita import circular

    output_dir = Path(config.settings.output_dir)
    now = (now or datetime.now()).astimezone()
    history = read_history(output_dir)
    reasons_critical: list[str] = []
    reasons_attention: list[str] = []

    expected = [p.name for p in config.enabled_platforms() if p.kind in COLLECTORS]
    platforms: dict[str, dict[str, Any]] = {name: {"ultimo_status": None, "ultima_coleta": None, "ultimo_sucesso": None}
                                            for name in expected}
    for entry in history:
        when = entry.get("fim") or entry.get("inicio")
        for name, info in (entry.get("plataformas") or {}).items():
            state = platforms.setdefault(name, {"ultimo_status": None, "ultima_coleta": None, "ultimo_sucesso": None})
            if info.get("status"):
                state["ultimo_status"] = info["status"]
                state["ultima_coleta"] = when
                if info["status"] == "sucesso":
                    state["ultimo_sucesso"] = when

    limit = config.settings.max_hours_without_success
    for name in expected:
        state = platforms[name]
        success = _parse(state["ultimo_sucesso"])
        state["horas_sem_sucesso"] = round((now - success).total_seconds() / 3600, 1) if success else None
        if success is None:
            reasons_critical.append(f"{name}: nenhuma coleta bem-sucedida registrada.")
        elif state["horas_sem_sucesso"] > limit:
            reasons_critical.append(f"{name}: {state['horas_sem_sucesso']:g} h sem coleta bem-sucedida (limite: {limit} h).")

    last = history[-1] if history else None
    if last is None:
        reasons_critical.append("Nenhuma execução registrada.")
    else:
        if last.get("estado") == "erro":
            reasons_critical.append(f"Última execução ({last['id']}) terminou com erro inesperado: {last.get('erro')}")
        elif last.get("status") == "falha":
            reasons_critical.append(f"Última execução ({last['id']}) falhou em todas as plataformas.")
        elif last.get("status") == "parcial":
            failed = [n for n, i in (last.get("plataformas") or {}).items() if i.get("status") != "sucesso"]
            reasons_attention.append(f"Última execução ({last['id']}) parcial: {', '.join(failed)}.")
        if last.get("falhas_relatorio") or last.get("falhas_pos_coleta"):
            reasons_attention.append(f"Relatório da última execução ({last['id']}) não foi gerado por completo.")
        warnings = sum(len(i.get("avisos") or []) for i in (last.get("plataformas") or {}).values())
        if warnings:
            reasons_attention.append(f"Última execução com {warnings} aviso(s) (ex.: dados incompletos).")

    running = running_manifests(output_dir)
    active = bool(running) and is_running(output_dir)
    if running and not active:
        reasons_attention.append(f"Execução interrompida sem conclusão: {', '.join(m['id'] for m in running)}.")

    health = "critico" if reasons_critical else ("atencao" if reasons_attention else "ok")
    return {
        "atualizado_em": now_iso(),
        "ambiente": config.environment,
        "saude": health,
        "motivos": reasons_critical + reasons_attention,
        "em_execucao": active,
        "ultima_execucao": {k: last.get(k) for k in ("id", "origem", "usuario", "inicio", "fim", "status", "estado")} if last else None,
        "plataformas": platforms,
        "limite_horas_sem_sucesso": limit,
    }


def write_status(config: AppConfig) -> dict[str, Any]:
    status = compute_health(config)
    output_dir = Path(config.settings.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(output_dir / STATUS_FILE, json.dumps(status, ensure_ascii=False, indent=2))
    return status

"""Execução das coletas: manual, agendada e reprocessamento (Épico 7).

Uma execução cria ``output/<data-hora>/`` com:
  * ``<plataforma>.json`` — resultado de cada coleta;
  * ``execucao.json``     — situação da execução, atualizada durante o andamento (Feature 7.3);
  * ``execucao.log``      — o mesmo progresso exibido no terminal, com horário;
  * ``consolidado.*`` e ``relatorio.*``.
Ao terminar, um resumo é acrescentado ao histórico ``output/historico.jsonl``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from jervis import driver
from jervis.audit import AuditLog, actor

from jervis.collection import failed_stages, merge_retry, new_run_dir, run_collection, save_result
from jervis.collectors import COLLECTORS, build_collector
from jervis.collectors.models import WARNING, CollectionResult, Issue, now_iso
from jervis.config import AppConfig, PlatformConfig, Settings
from jervis.consolidation import Options, consolidate, load_run, write_outputs
from jervis.credentials import CredentialStore, service_for
from jervis.errors import IssueCategory, JervisError
from jervis.fileutil import atomic_write_text
from jervis.health import write_status
from jervis.logging_setup import FILE_ONLY, current_run
from jervis.notify import Notifier
from jervis.reports import generate_reports
from jervis.security import mask_username

log = logging.getLogger(__name__)

MANIFEST = "execucao.json"
RUN_LOG = "execucao.log"
HISTORY = "historico.jsonl"
LOCK = ".jervis.lock"

STATUS_LABEL = {"sucesso": "OK", "parcial": "PARCIAL", "falha": "FALHA"}
EXIT_PARTIAL, EXIT_FAILED = 2, 3
STATE_LABEL = {"em_andamento": "em andamento", "concluida": "concluída", "interrompida": "interrompida", "pendente": "pendente"}
CLASSIFICATION_LABEL = {
    "critico": "crítico", "indisponivel": "indisponível", "falha_coleta": "falha de coleta",
    "atencao": "atenção", "normal": "normal",
}

CollectFn = Callable[..., CollectionResult]


class RunInProgressError(JervisError):
    """Já existe uma execução em andamento."""


class RunLock:
    """Impede duas execuções simultâneas (ex.: agendamento disparando durante uma coleta manual).

    Usa trava do sistema operacional no arquivo: se o processo morrer, a trava é liberada sozinha.
    """

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def __enter__(self) -> RunLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+")
        try:
            fh.seek(0)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            raise RunInProgressError(
                "Já existe uma coleta em andamento (outra janela ou um agendamento). "
                "Acompanhe com 'jervis runs' e tente novamente quando terminar."
            ) from None
        self._fh = fh
        return self

    def __exit__(self, *exc) -> None:
        if self._fh:
            try:
                self._fh.seek(0)
                if sys.platform == "win32":
                    import msvcrt

                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                self._fh.close()
                self._fh = None


class Progress:
    """Progresso com horário no terminal e em ``execucao.log``."""

    def __init__(self, out: Callable[[str], None] = print, clock: Callable[[], datetime] = datetime.now):
        self._out = out
        self._clock = clock
        self._file: Path | None = None

    def attach(self, path: Path) -> None:
        self._file = path

    def __call__(self, message: str) -> None:
        line = f"[{self._clock():%H:%M:%S}] {message}"
        self._out(line)
        log.info("%s", message, extra=FILE_ONLY)  # etapas também no log geral (com o id da execução)
        if self._file:
            with open(self._file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


@dataclass
class RunSummary:
    run_dir: Path
    status: str
    manifest: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        """0 = sucesso; 2 = parcial (ou relatório incompleto); 3 = falha (Feature 9.5)."""
        if self.status == "falha":
            return EXIT_FAILED
        report_problems = self.manifest.get("falhas_relatorio") or self.manifest.get("falhas_pos_coleta")
        return 0 if self.status == "sucesso" and not report_problems else EXIT_PARTIAL


def overall_status(results: list[CollectionResult]) -> str:
    statuses = {r.status for r in results}
    if not statuses or statuses == {"sucesso"}:
        return "sucesso" if statuses else "falha"
    return "falha" if statuses == {"falha"} else "parcial"


class Runner:
    def __init__(
        self,
        config: AppConfig,
        store: CredentialStore | None = None,
        emit: Progress | None = None,
        collect: CollectFn = run_collection,
        sleep: Callable[[float], None] = time.sleep,
        notifier: Notifier | None = None,
        driver_updater: Callable[[Settings], driver.DriverUpdate] = driver.update_for,
    ):
        self.config = config
        self.settings: Settings = config.settings
        self.store = store or CredentialStore(service_for(config.environment))
        self.emit = emit or Progress()
        self._collect = collect
        self._sleep = sleep
        self.output_dir = Path(self.settings.output_dir)
        self.audit = AuditLog(self.settings.audit_file, config.environment)
        self.notifier = notifier or Notifier(config.notifications, self.store)
        self._baseline: dict[str, dict[str, int]] = {}
        self._driver_updater = driver_updater

    # --- execução (7.1 / 7.2) ---------------------------------------------------------

    def run(
        self,
        platforms: list[PlatformConfig],
        origin: str = "manual",
        retries: int = 0,
        retry_delay: float = 0,
        formats: list[str] | None = None,
    ) -> RunSummary:
        with RunLock(self.output_dir / LOCK):
            run_dir = new_run_dir(self.output_dir)
            run_dir.mkdir(parents=True, exist_ok=True)
            token = current_run.set(run_dir.name)
            try:
                return self._run(run_dir, platforms, origin, retries, retry_delay, formats)
            finally:
                current_run.reset(token)

    def _run(self, run_dir, platforms, origin, retries, retry_delay, formats) -> RunSummary:
        self.emit.attach(run_dir / RUN_LOG)
        started = time.monotonic()
        manifest = self._new_manifest(run_dir, origin, [p.name for p in platforms])
        who = actor()
        where = f", ambiente {self.config.environment}" if self.config.environment else ""
        self.emit(f"Execução {run_dir.name} iniciada ({origin}{where}) por {who['usuario']} em {who['maquina']} "
                  f"— {len(platforms)} plataforma(s).")
        self.audit.record("coleta_iniciada", execucao=run_dir.name, origem=origin,
                          plataformas=[p.name for p in platforms], contas=self._accounts(platforms))
        self._baseline = last_successful_counts(self.output_dir)
        try:
            return self._run_body(run_dir, manifest, platforms, retries, retry_delay, formats, started)
        except Exception as exc:
            self._fail_run(manifest, run_dir, exc)
            raise JervisError(f"Erro inesperado na execução {run_dir.name}: {exc}. Detalhes em {self.settings.log_file}.") from exc

    def _run_body(self, run_dir, manifest, platforms, retries, retry_delay, formats, started) -> RunSummary:

        results: dict[str, CollectionResult] = {}
        runnable = [p for p in platforms if p.kind in COLLECTORS]
        for skipped in (p for p in platforms if p.kind not in COLLECTORS):
            self.emit(f"{skipped.name}: coleta não disponível para o tipo '{skipped.kind}' (ignorada).")
        if runnable:
            self._prepare_driver()
        for index, platform in enumerate(runnable, 1):
            self.emit(f"{platform.name} ({index}/{len(runnable)}): iniciando coleta")
            self._mark(manifest, platform.name, estado="em_andamento", inicio=now_iso())
            result = self._collect_platform(platform)
            self._check_completeness(result)
            results[platform.name] = result
            self._finish_platform(manifest, run_dir, result)

        by_name = {p.name: p for p in runnable}
        for attempt in range(1, retries + 1):
            pending = {n: s for n, r in results.items() if (s := failed_stages(r)) != set()}
            if not pending:
                break
            wait = f" em {retry_delay / 60:g} min" if retry_delay else ""
            self.emit(f"Reprocessamento automático {attempt}/{retries} de {', '.join(pending)}{wait}.")
            if retry_delay:
                self._sleep(retry_delay)
            for name, stages in pending.items():
                results[name] = self._retry_platform(by_name[name], results[name], stages, run_dir, manifest)

        summary = self._finish_run(manifest, run_dir, list(results.values()), started, formats)
        removed = prune_runs(self.output_dir, self.settings.retention_days, keep=run_dir)
        if removed:
            self.emit(f"Retenção: {len(removed)} pasta(s) de execução com mais de {self.settings.retention_days} dias removida(s).")
            self.audit.record("retencao_aplicada", pastas_removidas=removed, dias=self.settings.retention_days)
        return summary

    # --- reprocessamento (7.4) --------------------------------------------------------

    def retry(self, run_dir: Path, names: list[str] | None = None, formats: list[str] | None = None) -> RunSummary:
        with RunLock(self.output_dir / LOCK):
            token = current_run.set(run_dir.name)
            try:
                return self._retry(run_dir, names, formats)
            finally:
                current_run.reset(token)

    def _retry(self, run_dir: Path, names: list[str] | None, formats: list[str] | None) -> RunSummary:
        self.emit.attach(run_dir / RUN_LOG)
        started = time.monotonic()
        self._baseline = last_successful_counts(self.output_dir, exclude=run_dir.name)
        results = {r["platform"]: CollectionResult.from_dict(r) for r in load_run(run_dir)}
        manifest = self._load_manifest(run_dir, results)
        self.emit(f"Reprocessamento da execução {run_dir.name}.")
        selected = names or list(results)
        unknown = [n for n in selected if n not in results]
        if unknown:
            raise JervisError(f"Plataforma(s) sem resultado nesta execução: {', '.join(unknown)}.")

        retried = []
        driver_ready = False
        for name in selected:
            previous = results[name]
            stages = failed_stages(previous)
            if stages == set():
                reason = "requer correção da configuração" if previous.errors else "sem falhas"
                self.emit(f"{name}: nada a reprocessar ({reason}).")
                continue
            platform = self.config.platforms.get(name)
            if platform is None or not platform.enabled:
                self.emit(f"{name}: não está ativa na configuração atual; ignorada.")
                continue
            if not driver_ready:
                self._prepare_driver()
                driver_ready = True
            results[name] = self._retry_platform(platform, previous, stages, run_dir, manifest)
            retried.append(name)

        manifest.setdefault("reprocessamentos", []).append({"em": now_iso(), "plataformas": retried, **actor()})
        self.audit.record("reprocessamento", execucao=run_dir.name, plataformas=retried,
                          contas=self._accounts([self.config.platforms[n] for n in retried]))
        if not retried:
            self._save_manifest(run_dir, manifest)
            return RunSummary(run_dir, manifest.get("status", overall_status(list(results.values()))), manifest)
        return self._finish_run(manifest, run_dir, list(results.values()), started, formats, origin="reprocessamento")

    # --- etapas ---------------------------------------------------------------------

    def _prepare_driver(self) -> None:
        driver.prepare(self.settings, self.emit, self.audit.record, self._driver_updater)

    def _collect_platform(self, platform: PlatformConfig, only: set[str] | None = None) -> CollectionResult:
        return self._collect(
            platform, self.settings, self.store, only=only, progress=lambda m: self.emit(f"  · {platform.name}: {m}")
        )

    def _retry_platform(
        self, platform: PlatformConfig, previous: CollectionResult, stages: set[str] | None,
        run_dir: Path, manifest: dict[str, Any],
    ) -> CollectionResult:
        scope = "plataforma inteira" if stages is None else ", ".join(sorted(stages))
        self.emit(f"{platform.name}: reprocessando ({scope}) — tentativa {previous.attempts + 1}")
        self._mark(manifest, platform.name, estado="em_andamento")
        self._save_manifest(run_dir, manifest)
        merged = merge_retry(previous, self._collect_platform(platform, stages), stages)
        merged.issues = [i for i in merged.issues if i.category != IssueCategory.INCOMPLETE_DATA]
        self._check_completeness(merged)
        if stages is not None:
            try:  # recalcula destaques/cruzamentos sobre o resultado combinado
                build_collector(platform, self.settings).summarize(merged)
            except JervisError as exc:
                log.warning("[%s] Não foi possível recalcular o resumo: %s", platform.name, exc)
        self._finish_platform(manifest, run_dir, merged)
        return merged

    def _finish_platform(self, manifest: dict[str, Any], run_dir: Path, result: CollectionResult) -> None:
        save_result(result, run_dir)
        counts = " | ".join(f"{name}: {count}" for name, count in result.counts().items()) or "nenhum dado"
        self.emit(f"{result.platform}: [{STATUS_LABEL[result.status]}] {counts}")
        for dataset, situations in result.summary.get("destaques", {}).items():
            details = ", ".join(f"{count} {situation}" for situation, count in situations.items())
            self.emit(f"  destaque: {dataset}: {details}")
        for issue in result.issues:
            self.emit(f"  {issue.severity}: [{issue.category}] {issue.stage}: {issue.message}")
        self._mark(
            manifest, result.platform, estado="concluida", status=result.status, tentativas=result.attempts,
            contagens=result.counts(), fim=result.finished_at,
            falhas=[f"[{i.category}] {i.stage}: {i.message}" for i in result.errors],
            avisos=[f"[{i.category}] {i.stage}: {i.message}" for i in result.issues if i.severity == WARNING],
        )
        self._save_manifest(run_dir, manifest)

    def _finish_run(
        self, manifest: dict[str, Any], run_dir: Path, results: list[CollectionResult], started: float,
        formats: list[str] | None, origin: str | None = None,
    ) -> RunSummary:
        status = overall_status(results)
        manifest.pop("falhas_relatorio", None)
        manifest.pop("falhas_pos_coleta", None)
        if results:
            try:
                report = consolidate_run([r.to_dict() for r in results], run_dir, self.settings, self.emit)
                output = generate_run_reports(report, run_dir, self.settings,
                                              self.settings.report_formats if formats is None else formats, self.emit)
                manifest["consolidado"] = report["resumo"]["por_classificacao"]
                manifest["relatorios"] = sorted(p.name for paths in (output.files if output else {}).values() for p in paths)
                if output and output.errors:
                    manifest["falhas_relatorio"] = output.errors
            except Exception as exc:  # os dados coletados já estão salvos: registra e conclui a execução
                log.exception("Falha ao consolidar ou gerar relatórios")
                manifest["falhas_pos_coleta"] = f"{type(exc).__name__}: {exc}"
                self.emit(f"ERRO ao consolidar/gerar relatórios: {exc}. Os resultados da coleta foram salvos; "
                          f"tente novamente com 'jervis report {run_dir}'.")
        elapsed = round(time.monotonic() - started, 1)
        if origin == "reprocessamento":
            # A duração da execução original é preservada; o reprocessamento registra a sua.
            manifest["reprocessamentos"][-1]["duracao_s"] = elapsed
            manifest.update(estado="concluida", status=status)
        else:
            manifest.update(estado="concluida", status=status, fim=now_iso(), duracao_s=elapsed)
        self._save_manifest(run_dir, manifest)
        self._append_history({**manifest, "origem": origin or manifest["origem"], "duracao_s": elapsed})
        self.audit.record(
            "reprocessamento_concluido" if origin == "reprocessamento" else "coleta_concluida",
            execucao=run_dir.name, status=status, duracao_s=elapsed,
            plataformas={r.platform: r.status for r in results},
            falhas_relatorio=manifest.get("falhas_relatorio") or manifest.get("falhas_pos_coleta"),
        )
        ok = sum(1 for r in results if r.status == "sucesso")
        what = "Reprocessamento da execução {} concluído" if origin == "reprocessamento" else "Execução {} concluída"
        self._after_run(manifest, run_dir)
        self.emit(f"{what.format(run_dir.name)}: [{STATUS_LABEL[status]}] {ok} de {len(results)} plataforma(s) "
                  f"sem erros, em {elapsed:.0f}s. Resultados em {run_dir.resolve()}")
        return RunSummary(run_dir, status, manifest)

    # --- qualidade, auditoria e falhas -------------------------------------------------

    def _check_completeness(self, result: CollectionResult) -> None:
        """Dados incompletos: conjunto com bem menos registros que na última coleta bem-sucedida.

        Pega falhas silenciosas (filtro alterado, permissão reduzida do usuário de coleta,
        mudança na plataforma) que não geram erro de tela. Conjuntos com página em erro
        já explicam a queda e são ignorados.
        """
        previous = self._baseline.get(result.platform, {})
        failed_datasets = {i.stage.split("/")[0] for i in result.errors}
        threshold = self.settings.incomplete_drop_pct / 100
        for dataset, rows in result.datasets.items():
            before, now = previous.get(dataset), len(rows)
            if not before or dataset in failed_datasets:
                continue
            if (now == 0) or (threshold and before >= 5 and now < before * (1 - threshold)):
                drop = round(100 * (before - now) / before)
                result.add_issue(Issue(
                    stage=f"completude/{dataset}", category=IssueCategory.INCOMPLETE_DATA, severity=WARNING,
                    message=f"{dataset}: {now} registro(s), {drop}% a menos que na última coleta bem-sucedida ({before}). "
                            "Verifique filtros, permissões do usuário de coleta ou mudanças na plataforma.",
                ))

    def _accounts(self, platforms: list[PlatformConfig]) -> dict[str, dict[str, str | None]]:
        """Conta de serviço usada em cada plataforma (mascarada) e de onde veio a credencial."""
        accounts = {}
        for p in platforms:
            try:
                status = self.store.status(p.name)
                username = self.store.get(p.name).username if status.configured else None
                accounts[p.name] = {"usuario": mask_username(username) if username else None, "credencial": status.source}
            except Exception:  # auditoria nunca impede a coleta
                accounts[p.name] = {"usuario": None, "credencial": None}
        return accounts

    def _fail_run(self, manifest: dict[str, Any], run_dir: Path, exc: Exception) -> None:
        log.exception("Erro inesperado na execução %s", run_dir.name)
        manifest.update(estado="erro", status="falha", fim=now_iso(), erro=f"{type(exc).__name__}: {exc}")
        self._save_manifest(run_dir, manifest)
        self._append_history(manifest)
        self.audit.record("coleta_erro", execucao=run_dir.name, erro=manifest["erro"])
        self.emit(f"ERRO inesperado: {exc}. A execução foi encerrada; detalhes em {self.settings.log_file}.")
        self._after_run(manifest, run_dir)

    def _after_run(self, manifest: dict[str, Any], run_dir: Path) -> None:
        """Notificação e status da ferramenta. Nada aqui pode derrubar a execução."""
        try:
            if self.notifier.should_notify(manifest):
                errors = self.notifier.notify(manifest, run_dir)
                if errors:
                    manifest["falhas_notificacao"] = errors
                    self._save_manifest(run_dir, manifest)
                    self.audit.record("notificacao_falhou", execucao=run_dir.name, falhas=errors)
                    self.emit("Notificação não enviada: " + "; ".join(f"{k}: {v}" for k, v in errors.items()))
                else:
                    self.emit("Notificação enviada.")
        except Exception:
            log.exception("Falha inesperada ao notificar")
        try:
            write_status(self.config)
        except Exception:
            log.exception("Falha ao atualizar status.json")

    # --- manifesto e histórico ----------------------------------------------------------

    def _new_manifest(self, run_dir: Path, origin: str, names: list[str]) -> dict[str, Any]:
        manifest = {
            "id": run_dir.name, "origem": origin, "ambiente": self.config.environment, **actor(), "estado": "em_andamento", "status": None, "pid": os.getpid(),
            "inicio": now_iso(), "fim": None, "duracao_s": None,
            "plataformas": {name: {"estado": "pendente"} for name in names},
        }
        self._save_manifest(run_dir, manifest)
        return manifest

    def _load_manifest(self, run_dir: Path, results: dict[str, CollectionResult]) -> dict[str, Any]:
        path = run_dir / MANIFEST
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {  # execuções anteriores ao Épico 7: reconstrói a partir dos resultados
            "id": run_dir.name, "origem": "desconhecida", "inicio": None, "plataformas": {
                n: {"estado": "concluida", "status": r.status, "tentativas": r.attempts} for n, r in results.items()
            },
        }

    @staticmethod
    def _mark(manifest: dict[str, Any], name: str, **values: Any) -> None:
        manifest["plataformas"].setdefault(name, {}).update(values)

    @staticmethod
    def _save_manifest(run_dir: Path, manifest: dict[str, Any]) -> None:
        atomic_write_text(run_dir / MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))

    def _append_history(self, manifest: dict[str, Any]) -> None:
        entry = {k: v for k, v in manifest.items() if k != "pid"}
        with open(self.output_dir / HISTORY, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


# --- consolidação e relatórios (compartilhado com os comandos consolidate/report) -------


def consolidate_run(results: list[dict[str, Any]], run_dir: Path, settings: Settings, emit: Callable[[str], None]) -> dict:
    options = Options(stale_device_days=settings.stale_device_days, critical_availability_pct=settings.critical_availability_pct)
    report = consolidate(results, options)
    json_path, csv_path = write_outputs(report, run_dir)
    summary, validation = report["resumo"], report["validacao"]
    counts = " | ".join(f"{CLASSIFICATION_LABEL[c]}: {n}" for c, n in summary["por_classificacao"].items())
    emit(f"Consolidado: {summary['total']} registro(s)" + (f" | {counts}" if counts else ""))
    notes = []
    if validation["duplicados_removidos"]:
        notes.append(f"{validation['duplicados_removidos']} duplicado(s) removido(s)")
    if validation["descartados"]:
        notes.append(f"{len(validation['descartados'])} descartado(s) por dados inválidos")
    if validation["com_observacoes"]:
        notes.append(f"{validation['com_observacoes']} com observações")
    if notes:
        emit(f"  ({', '.join(notes)})")
    emit(f"  Arquivos: {json_path} e {csv_path.name}")
    return report


def generate_run_reports(report: dict, run_dir: Path, settings: Settings, formats, emit: Callable[[str], None],
                         meta: dict | None = None, basename: str = "relatorio"):
    if not formats:
        return None
    output = generate_reports(report, run_dir, formats, settings, meta=meta, basename=basename)
    for fmt in formats:
        if fmt in output.files:
            emit(f"  Relatório {fmt.upper()}: {', '.join(p.name for p in output.files[fmt])}")
        else:
            emit(f"  Relatório {fmt.upper()}: não gerado — {output.errors[fmt]}")
    return output


def last_successful_counts(output_dir: Path, exclude: str | None = None) -> dict[str, dict[str, int]]:
    """Contagens da última coleta bem-sucedida de cada plataforma (base para detectar dados incompletos)."""
    baseline: dict[str, dict[str, int]] = {}
    for entry in read_history(output_dir):
        if entry.get("id") == exclude:
            continue
        for name, info in (entry.get("plataformas") or {}).items():
            if info.get("status") == "sucesso" and info.get("contagens"):
                baseline[name] = info["contagens"]
    return baseline


_RUN_DIR = re.compile(r"\d{8}-\d{6}")


def prune_runs(output_dir: Path, days: int, keep: Path | None = None, now: datetime | None = None) -> list[str]:
    """Remove pastas de execução com mais de ``days`` dias. O histórico (historico.jsonl) é mantido."""
    if days <= 0 or not output_dir.is_dir():
        return []
    limit = (now or datetime.now()) - timedelta(days=days)
    removed = []
    for folder in sorted(output_dir.iterdir()):
        if not folder.is_dir() or not _RUN_DIR.fullmatch(folder.name) or (keep and folder.resolve() == keep.resolve()):
            continue
        try:
            started = datetime.strptime(folder.name, "%Y%m%d-%H%M%S")
        except ValueError:
            continue
        if started < limit:
            shutil.rmtree(folder, ignore_errors=True)
            removed.append(folder.name)
    return removed


def read_history(output_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    path = output_dir / HISTORY
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries[-limit:] if limit else entries


def is_running(output_dir: Path) -> bool:
    """Há uma execução em andamento (a trava está ocupada)?"""
    try:
        with RunLock(output_dir / LOCK):
            return False
    except RunInProgressError:
        return True


def running_manifests(output_dir: Path) -> list[dict[str, Any]]:
    """Execuções marcadas como em andamento (para acompanhamento a partir de outro terminal)."""
    if not output_dir.is_dir():
        return []
    manifests = []
    for path in sorted(output_dir.glob(f"*/{MANIFEST}")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("estado") == "em_andamento":
            manifests.append(data)
    return manifests

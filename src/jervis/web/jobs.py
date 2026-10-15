"""Fila das gerações pedidas pela interface (gerar de novo o relatório de um cliente): uma de cada vez, em
segundo plano, para a página não ficar presa enquanto o Jervis coleta e imprime os PDFs."""

from __future__ import annotations

import itertools
import logging
import queue
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Callable

log = logging.getLogger(__name__)

WAITING, RUNNING, DONE, FAILED = "na_fila", "gerando", "concluido", "falha"


@dataclass
class Job:
    id: int
    customer_id: int
    customer: str
    competencia: str
    requested_by: str
    status: str = WAITING
    message: str = ""
    report_id: int | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished_at: str | None = None


class Jobs:
    def __init__(self, worker: Callable[[Job], tuple[str, int | None, str]], keep: int = 50, start: bool = True):
        """``worker(job)`` gera o relatório e devolve (resultado, id da revisão, detalhe)."""
        self._worker, self._keep = worker, keep
        self._jobs: dict[int, Job] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._queue: queue.Queue[Job] = queue.Queue()
        if start:
            threading.Thread(target=self._loop, name="jervis-web-jobs", daemon=True).start()

    def submit(self, customer_id: int, customer: str, competencia: str, requested_by: str) -> Job:
        with self._lock:
            for job in self._jobs.values():  # o mesmo pedido duas vezes: devolve o que já está na fila
                if job.customer_id == customer_id and job.competencia == competencia and job.status in (WAITING, RUNNING):
                    return job
            job = Job(next(self._ids), customer_id, customer, competencia, requested_by)
            self._jobs[job.id] = job
            for old in sorted(self._jobs)[:-self._keep]:
                if self._jobs[old].status in (DONE, FAILED):
                    del self._jobs[old]
        self._queue.put(job)
        return job

    def list(self) -> list[dict]:
        with self._lock:
            return [asdict(j) for j in sorted(self._jobs.values(), key=lambda j: j.id, reverse=True)]

    def run_next(self) -> None:
        """Executa o próximo da fila (a thread chama em laço; os testes, diretamente)."""
        job = self._queue.get()
        job.status = RUNNING
        try:
            resultado, report_id, detail = self._worker(job)
            job.status, job.report_id = (FAILED if resultado == "falha" else DONE), report_id
            job.message = {"sucesso": "Relatório gerado, pendente de revisão.",
                           "parcial": f"Gerado com limitações ({detail}), pendente de revisão."}.get(
                resultado, detail or "Nenhum dado coletado.")
        except Exception as exc:  # noqa: BLE001 - a fila continua para os próximos pedidos
            log.exception("Geração pedida pela interface falhou (%s, %s)", job.customer, job.competencia)
            job.status, job.message = FAILED, f"Erro inesperado: {type(exc).__name__}"
        finally:
            job.finished_at = datetime.now().isoformat(timespec="seconds")
            self._queue.task_done()

    def _loop(self) -> None:
        while True:
            self.run_next()

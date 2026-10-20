import math
import multiprocessing
import os
import time
from collections.abc import Iterable
from multiprocessing.connection import Connection
from queue import Empty, Queue
from threading import Event, Thread

from .engine import ScanEngine
from .models import AnalysisReport
from .policy import ScanError, ScanPolicy
from .transport import decode_message, encode_message

class ScanCancelled(ScanError):
    pass

def _apply_resource_limits(policy: ScanPolicy) -> dict:
    state = {
        "separate_process": True,
        "hard_timeout": True,
        "memory_limit_enforced": False,
        "cpu_limit_enforced": False,
        "network_calls_by_engine": False,
        "sandbox": False,
        "report_transport": "bounded_validated_json",
        "pickle_reports": False,
        "max_report_bytes": policy.max_report_bytes,
    }
    if os.name != "posix":
        state["resource_limit_note"] = (
            "Limites de memória do sistema não estão disponíveis neste backend; o prazo e o cancelamento continuam ativos."
        )
        return state
    import resource

    limits = (
        (resource.RLIMIT_AS, policy.max_memory_mb * 1024 * 1024, "memory_limit_enforced"),
        (resource.RLIMIT_CPU, math.ceil(policy.timeout_seconds) + 1, "cpu_limit_enforced"),
        (resource.RLIMIT_CORE, 0, "core_dumps_disabled"),
    )
    for kind, requested, key in limits:
        try:
            _, hard = resource.getrlimit(kind)
            maximum = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
            resource.setrlimit(kind, (maximum, maximum))
            state[key] = True
        except (OSError, ValueError) as error:
            state[f"{key}_error"] = str(error)
    return state

def _worker(
    connection: Connection,
    filename: str,
    policy: ScanPolicy,
    hashes: tuple[str, ...],
    expected_sha256: str | None,
) -> None:
    try:
        isolation = _apply_resource_limits(policy)
        report = ScanEngine(policy, hashes, expected_sha256=expected_sha256).scan(filename)
        report.root.metadata["isolation"] = isolation
        connection.send_bytes(encode_message("report", report, policy.max_report_bytes))
    except BaseException as error:
        try:
            message = f"{type(error).__name__}: {error}"[:4096]
            connection.send_bytes(encode_message("error", message, policy.max_report_bytes))
        except (OSError, EOFError, MemoryError, ScanError):
            pass
    finally:
        connection.close()

def scan_isolated(
    filename: str | os.PathLike[str],
    policy: ScanPolicy | None = None,
    known_hashes: Iterable[str] = (),
    expected_sha256: str | None = None,
    cancel: Event | None = None,
) -> AnalysisReport:
    policy = policy or ScanPolicy()
    hashes = tuple(known_hashes)
    ScanEngine(policy, hashes, expected_sha256=expected_sha256)
    if cancel is not None and cancel.is_set():
        raise ScanCancelled("Análise cancelada; nenhum veredito de segurança foi emitido.")
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker,
        args=(sending, os.fspath(filename), policy, hashes, expected_sha256),
        daemon=True,
    )
    responses: Queue[tuple[str, object]] = Queue(maxsize=1)

    def receive() -> None:
        try:
            data = receiving.recv_bytes(maxlength=policy.max_report_bytes)
            responses.put(decode_message(data, policy))
        except (EOFError, OSError, MemoryError, ScanError) as error:
            responses.put(
                (
                    "error",
                    f"O processo não forneceu um relatório válido: {type(error).__name__}: {error}",
                )
            )

    started = time.monotonic()
    thread = Thread(target=receive, daemon=True)
    launched = False
    try:
        process.start()
        launched = True
        sending.close()
        thread.start()
        while True:
            if cancel is not None and cancel.is_set():
                raise ScanCancelled("Análise cancelada; o processo foi encerrado.")
            remaining = policy.timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise ScanError(
                    "Prazo rígido atingido; o processo foi encerrado sem emitir um veredito de segurança."
                )
            try:
                kind, result = responses.get(timeout=min(0.05, remaining))
            except Empty:
                continue
            if kind == "report" and isinstance(result, AnalysisReport):
                return result
            raise ScanError(str(result))
    finally:
        if launched:
            process.join(timeout=0.15)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            process.close()
        sending.close()
        receiving.close()
        if thread.is_alive():
            thread.join(timeout=0.2)

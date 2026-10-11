"""Współbieżny runner z limitem równoległości i budżetem czasu.

Naprawia dwie wady z audytu:
  * brak limitu równoległości (holehe startował 123 zadania naraz),
  * zbiorcze łapanie wyjątków bez typu.

Runner wywołuje konektory z semaforem, per-konektorowym timeoutem i mapuje
typowane wyjątki na :class:`Status`. Pojedynczy konektor nigdy nie wywraca
całości — błąd staje się :class:`Finding` o statusie ERROR/UNKNOWN.
"""
from __future__ import annotations

import asyncio
from typing import List, Sequence

from .connector import Connector, Context
from .errors import ConnectorError
from .model import Finding, Status, Subject
from .privacy import subject_ref


def _finding_from_exception(connector: Connector, ref: str, exc: BaseException) -> Finding:
    if isinstance(exc, ConnectorError):
        status = Status.UNKNOWN if exc.maps_to_unknown else Status.ERROR
        kind = exc.error_kind
    elif isinstance(exc, asyncio.TimeoutError):
        status, kind = Status.ERROR, "timeout"
    else:
        # Nieoczekiwany wyjątek — jawnie ERROR/unexpected, nigdy "nie znaleziono".
        status, kind = Status.ERROR, "unexpected"
    return Finding(
        connector=connector.name,
        source=connector.source_kind,
        status=status,
        confidence=0.0,
        subject_ref=ref,
        evidence=f"{type(exc).__name__}",
        error_kind=kind,
    )


async def _run_one(
    connector: Connector,
    subject: Subject,
    ctx: Context,
    ref: str,
    sem: asyncio.Semaphore,
) -> Finding:
    async with sem:
        supported = getattr(connector, "supported_inputs", None)
        if supported is not None and subject.kind not in supported:
            # Niezgodny typ wejścia odrzucamy PRZED wywołaniem konektora — klient HTTP nie jest dotykany.
            return Finding(
                connector=connector.name,
                source=connector.source_kind,
                status=Status.UNKNOWN,
                confidence=0.0,
                subject_ref=ref,
                evidence=f"typ wejścia {subject.kind.value} niewspierany przez konektor",
                error_kind="unsupported_input",
            )
        try:
            result = await asyncio.wait_for(connector.check(subject, ctx), ctx.timeout)
        except BaseException as exc:  # mapujemy po typie w _finding_from_exception
            if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            return _finding_from_exception(connector, ref, exc)
        # Twardy kontrakt: konektor musi zwrócić Finding dla właściwego celu.
        if not isinstance(result, Finding):
            return _finding_from_exception(
                connector, ref, ConnectorError("konektor nie zwrócił Finding")
            )
        if result.subject_ref != ref:
            object.__setattr__(result, "subject_ref", ref)
        return result


async def run(
    connectors: Sequence[Connector],
    subject: Subject,
    ctx: Context,
    *,
    concurrency: int = 10,
) -> List[Finding]:
    """Uruchom konektory współbieżnie; zwróć wyniki posortowane po nazwie.

    Każdy konektor dostaje ten sam ``subject_ref`` (hash celu). Wyjątki nie
    propagują — stają się Finding(ERROR/UNKNOWN).
    """
    if concurrency < 1:
        raise ValueError("concurrency musi być >= 1")
    ref = subject_ref(subject, ctx.salt)
    sem = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(_run_one(c, subject, ctx, ref, sem)) for c in connectors
    ]
    findings = await asyncio.gather(*tasks)
    return sorted(findings, key=lambda f: f.connector)


def summarize(findings: Sequence[Finding]) -> dict:
    """Deterministyczne podsumowanie liczności per status (do raportu/panelu)."""
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
    return counts

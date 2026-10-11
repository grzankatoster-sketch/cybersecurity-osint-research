"""One fair dispatcher; lazy jobs, bounded logical work, no sleeping retry workers."""

from __future__ import annotations

import asyncio
import math
from collections import Counter, deque
from collections.abc import AsyncGenerator, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from time import monotonic
from typing import Generic, Protocol, TypeVar

from ultimate_username.domain.models import ErrorCode, SearchError

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)


class Work(Protocol[T_co]):
    @property
    def origin(self) -> str: ...
    @property
    def concurrency(self) -> int: ...
    @property
    def interval(self) -> float: ...
    @property
    def ready_at(self) -> float: ...
    @property
    def expires_at(self) -> float: ...
    async def step(self) -> bool: ...
    def result(self) -> T_co: ...
    def fail(self, error: SearchError) -> T_co: ...


@dataclass(frozen=True, slots=True)
class SchedulerConfig:
    concurrency: int = 20
    per_origin: int = 2
    per_job: int = 10
    queue_capacity: int = 128
    job_buffer: int = 32
    max_jobs: int = 32
    origin_limits: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        values = (
            self.concurrency,
            self.per_origin,
            self.per_job,
            self.queue_capacity,
            self.job_buffer,
            self.max_jobs,
            *(n for _, n in self.origin_limits),
        )
        if any(type(n) is not int or n < 1 for n in values):
            raise ValueError("Scheduler limits must be positive integers")


@dataclass(slots=True)
class SchedulerStats:
    admitted: int = 0
    completed: int = 0
    cancelled: int = 0
    peak_active: int = 0
    peak_pending: int = 0
    peak_tasks: int = 0
    origin_peak: Counter[str] = field(default_factory=Counter)


@dataclass(eq=False)
class _Job(Generic[T]):
    source: Iterator[Work[T]]
    output: asyncio.Queue[T | Exception | None]
    outstanding: int = 0
    active: int = 0
    exhausted: bool = False
    cancelled: bool = False
    ended: bool = False
    limit: int | None = None  # per-job cap below SchedulerConfig.per_job (lower concurrency)


class Scheduler(Generic[T]):
    def __init__(self, config: SchedulerConfig | None = None) -> None:
        self.config = config or SchedulerConfig()
        self.stats = SchedulerStats()
        self._jobs: deque[_Job[T]] = deque()
        self._pending: deque[tuple[_Job[T], Work[T]]] = deque()
        self._active: dict[asyncio.Task[None], tuple[_Job[T], str]] = {}
        self._origins: Counter[str] = Counter()
        self._next_origin: dict[str, float] = {}
        self._limits: Mapping[str, int] = dict(self.config.origin_limits)
        self._wake = asyncio.Event()
        self._driver: asyncio.Task[None] | None = None
        self._closed = False

    def cooldown(self, host: str, until: float) -> None:
        if math.isfinite(until):
            self._next_origin[host] = max(self._next_origin.get(host, 0), until)
            self._wake.set()

    async def stream(
        self, source: Iterable[Work[T]], *, limit: int | None = None
    ) -> AsyncGenerator[T, None]:
        if self._closed:
            raise RuntimeError("Scheduler closed")
        if len(self._jobs) >= self.config.max_jobs:
            raise ValueError("Maximum concurrent jobs reached")
        if limit is not None and limit < 1:
            raise ValueError("Job concurrency limit must be positive")
        job = _Job(iter(source), asyncio.Queue(self.config.job_buffer + 1), limit=limit)
        self._jobs.append(job)
        if self._driver is None:
            self._driver = asyncio.create_task(self._drive(), name="uee-dispatcher")
        self._wake.set()
        try:
            while True:
                item = await job.output.get()
                self._wake.set()
                if item is None:
                    break
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            await self._cancel_job(job)

    def _finish(self, job: _Job[T], value: T) -> None:
        job.outstanding -= 1
        self.stats.completed += 1
        if not job.cancelled:
            job.output.put_nowait(value)

    async def _execute(self, job: _Job[T], work: Work[T], host: str) -> None:
        try:
            if await work.step():
                self._finish(job, work.result())
            elif not job.cancelled:
                # A bounded public fallback continues an admitted canonical service.
                # Prioritize it over fresh primary slots so small budgets do not
                # starve fallbacks behind the already buffered registry queue.
                if getattr(work, "continuation_priority", False):
                    self._pending.appendleft((job, work))
                else:
                    self._pending.append((job, work))
        except asyncio.CancelledError:
            self.stats.cancelled += 1
            job.outstanding -= 1
            work.fail(SearchError(ErrorCode.CANCELLED, "scheduler", "Job cancelled"))
            raise
        except Exception as exc:
            self._finish(
                job,
                work.fail(SearchError(ErrorCode.INTERNAL_ERROR, "scheduler", type(exc).__name__)),
            )
        finally:
            job.active -= 1
            self._origins[host] -= 1
            task = asyncio.current_task()
            if task is not None:
                self._active.pop(task, None)
            self._wake.set()

    def _admit(self) -> None:
        # Reserve a pending slot for every active request that may retry/redirect.
        capacity = self.config.queue_capacity - len(self._pending) - len(self._active)
        stalled = 0
        while self._jobs and capacity > 0 and stalled < len(self._jobs):
            job = self._jobs[0]
            self._jobs.rotate(-1)
            if (
                job.exhausted
                or job.cancelled
                or job.outstanding + job.output.qsize() >= self.config.job_buffer
            ):
                stalled += 1
                continue
            try:
                work = next(job.source)
            except StopIteration:
                job.exhausted = True
                stalled += 1
                continue
            except Exception as exc:
                job.exhausted = True
                job.output.put_nowait(RuntimeError("Work source failed: " + type(exc).__name__))
                stalled += 1
                continue
            job.outstanding += 1
            self.stats.admitted += 1
            self._pending.append((job, work))
            capacity -= 1
            stalled = 0
        self.stats.peak_pending = max(self.stats.peak_pending, len(self._pending))

    def _dispatch(self) -> float | None:
        now = monotonic()
        next_wake = math.inf
        for _ in range(len(self._pending)):
            job, work = self._pending.popleft()
            if now >= work.expires_at:
                self._finish(
                    job,
                    work.fail(
                        SearchError(ErrorCode.QUEUE_TIMEOUT, "queue", "Work deadline exceeded")
                    ),
                )
                continue
            host = work.origin
            limit = min(work.concurrency, self._limits.get(host, self.config.per_origin))
            ready = max(work.ready_at, self._next_origin.get(host, 0))
            available = (
                len(self._active) < self.config.concurrency
                and job.active < min(self.config.per_job, job.limit or self.config.per_job)
                and self._origins[host] < limit
            )
            if available and now >= ready:
                job.active += 1
                self._origins[host] += 1
                self._next_origin[host] = now + work.interval
                task = asyncio.create_task(self._execute(job, work, host), name="uee-attempt")
                self._active[task] = (job, host)
                self.stats.peak_active = max(self.stats.peak_active, len(self._active))
                self.stats.origin_peak[host] = max(
                    self.stats.origin_peak[host], self._origins[host]
                )
            else:
                self._pending.append((job, work))
                next_wake = min(next_wake, work.expires_at)
                if available:
                    next_wake = min(next_wake, ready)
        self.stats.peak_tasks = max(self.stats.peak_tasks, len(self._active) + 1)
        return max(0.001, next_wake - now) if math.isfinite(next_wake) else None

    async def _drive(self) -> None:
        while not self._closed:
            self._wake.clear()
            self._admit()
            delay = self._dispatch()
            for job in tuple(self._jobs):
                if job.exhausted and job.outstanding == 0 and not job.ended:
                    job.output.put_nowait(None)
                    job.ended = True
            # Drop expired cooldown metadata once no work references the host.
            now = monotonic()
            self._next_origin = {h: t for h, t in self._next_origin.items() if t > now}
            self._origins += Counter()  # remove zero entries
            try:
                if delay is None:
                    await self._wake.wait()
                else:
                    await asyncio.wait_for(self._wake.wait(), delay)
            except TimeoutError:
                pass

    async def _cancel_job(self, job: _Job[T]) -> None:
        if job.cancelled:
            return
        job.cancelled = True
        kept: deque[tuple[_Job[T], Work[T]]] = deque()
        for owner, work in self._pending:
            if owner is job:
                self.stats.cancelled += 1
                job.outstanding -= 1
                work.fail(SearchError(ErrorCode.CANCELLED, "scheduler", "Job cancelled"))
            else:
                kept.append((owner, work))
        self._pending = kept
        tasks = [t for t, (owner, _) in self._active.items() if owner is job]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if job in self._jobs:
            self._jobs.remove(job)
        self._wake.set()

    async def close(self) -> None:
        self._closed = True
        self._wake.set()
        for job in tuple(self._jobs):
            await self._cancel_job(job)
            if not job.ended:
                job.output.put_nowait(None)
                job.ended = True
        if self._driver:
            await self._driver
            self._driver = None

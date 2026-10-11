"""Killable parser workers; process startup is measured separately from parsing."""

from __future__ import annotations

import asyncio
import multiprocessing
from multiprocessing.connection import Connection
from time import monotonic

from ultimate_username.domain.metadata import MetadataState, ProfileMetadata
from ultimate_username.domain.models import DetectionResult, SiteDefinition, TransportResponse
from ultimate_username.enrichment import enrich
from ultimate_username.extraction import ExtractionConfig


def _profile_worker(
    connection: Connection,
    response: TransportResponse,
    username: str,
    site: SiteDefinition,
    detection: DetectionResult,
    control_digests: frozenset[str] = frozenset(),
    follow_up: bool = False,
) -> None:
    try:
        connection.send(
            enrich(
                response,
                username,
                site,
                detection,
                control_digests=control_digests,
                follow_up=follow_up,
            )
        )
    finally:
        connection.close()


class ProfileService:
    def __init__(self, config: ExtractionConfig | None = None) -> None:
        self.config = config or ExtractionConfig()
        self._semaphore = asyncio.Semaphore(self.config.workers)

    async def run(
        self,
        response: TransportResponse,
        username: str,
        site: SiteDefinition,
        detection: DetectionResult,
        control_digests: frozenset[str] = frozenset(),
        follow_up: bool = False,
    ) -> ProfileMetadata:
        if len(response.body) > self.config.body_limit:
            return ProfileMetadata(MetadataState.ERROR, errors=("body limit",), parser_failures=1)
        async with self._semaphore:
            context = multiprocessing.get_context("spawn")
            receiving, sending = context.Pipe(duplex=False)
            process = context.Process(
                target=_profile_worker,
                args=(sending, response, username, site, detection, control_digests, follow_up),
                daemon=True,
            )
            try:
                process.start()
                sending.close()
                deadline = monotonic() + self.config.timeout
                while monotonic() < deadline:
                    if receiving.poll():
                        result: object = receiving.recv()
                        if not isinstance(result, ProfileMetadata):
                            raise ValueError("Invalid profile result")
                        return result
                    if not process.is_alive():
                        raise ValueError("Profile worker exited")
                    await asyncio.sleep(0.005)
                return ProfileMetadata(
                    MetadataState.TIMEOUT, errors=("parser deadline",), parser_failures=1
                )
            except (ValueError, OSError, EOFError) as exc:
                return ProfileMetadata(
                    MetadataState.ERROR, errors=(type(exc).__name__,), parser_failures=1
                )
            finally:
                if process.pid is not None:
                    if process.is_alive():
                        process.terminate()
                    process.join(timeout=0.5)
                    if process.is_alive():
                        process.kill()
                        process.join()
                    process.close()
                receiving.close()
                sending.close()

"""Konektor PASSIVE (offline) — dopasowanie do danych własnych.

Nie wykonuje żadnego ruchu sieciowego i nie dotyka celu. Sprawdza, czy
zahaszowany identyfikator celu występuje w dostarczonym zbiorze danych
(``ctx.dataset["known_refs"]`` — zbiór ``subject_ref``). Wzorzec dla
pasywnego wzbogacania na podstawie danych, które już legalnie posiadamy.
"""
from __future__ import annotations

from ..connector import Context, connector
from ..errors import ParseError
from ..model import Finding, InputKind, SourceKind, Status, Subject
from ..privacy import subject_ref


@connector
class PassiveLocalDataset:
    name = "passive_local_dataset"
    source_kind = SourceKind.PASSIVE
    supported_inputs = frozenset({InputKind.EMAIL, InputKind.PHONE})

    async def check(self, subject: Subject, ctx: Context) -> Finding:
        if ctx.dataset is None or "known_refs" not in ctx.dataset:
            # Brak danych to niepewność, nie negatyw.
            return Finding(
                connector=self.name,
                source=self.source_kind,
                status=Status.UNKNOWN,
                confidence=0.0,
                subject_ref="",
                evidence="brak zbioru danych w kontekście",
                error_kind="no_dataset",
            )
        known = ctx.dataset["known_refs"]
        if not isinstance(known, (set, frozenset, list, tuple)):
            raise ParseError("known_refs ma nieprawidłowy typ")
        ref = subject_ref(subject, ctx.salt)
        hit = ref in set(known)
        return Finding(
            connector=self.name,
            source=self.source_kind,
            status=Status.FOUND if hit else Status.NOT_FOUND,
            confidence=1.0 if hit else 0.9,  # negatyw nie jest w 100% pewny
            subject_ref=ref,
            evidence="dopasowanie w danych własnych" if hit else "brak w danych własnych",
        )

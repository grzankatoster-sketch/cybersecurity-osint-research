"""Konektor MANUAL — nie sprawdza nic automatycznie.

Zwraca UNKNOWN z podpowiedzią do ręcznego potwierdzenia przez analityka. To
bezpieczny wzorzec dla serwisów, których nie wolno sondować automatycznie —
zamiast aktywnej enumeracji oddaje decyzję człowiekowi.
"""
from __future__ import annotations

from ..connector import Context, connector
from ..model import Finding, InputKind, SourceKind, Status, Subject


@connector
class ManualConfirm:
    name = "manual_confirm"
    source_kind = SourceKind.MANUAL
    supported_inputs = frozenset({InputKind.EMAIL, InputKind.PHONE, InputKind.USERNAME})

    async def check(self, subject: Subject, ctx: Context) -> Finding:
        return Finding(
            connector=self.name,
            source=self.source_kind,
            status=Status.UNKNOWN,
            confidence=0.0,
            subject_ref="",  # uzupełni runner
            evidence="wymaga ręcznego potwierdzenia przez analityka",
            error_kind="manual_required",
            extra={"input_kind": subject.kind.value},
        )

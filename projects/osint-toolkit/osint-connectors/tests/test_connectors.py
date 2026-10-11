"""Testy konektorów referencyjnych + odkrywania przez rejestr pakietowy."""
import asyncio

from osint_connectors import Context, InputKind, Status, Subject, run
from osint_connectors.connector import ConnectorRegistry
from osint_connectors.privacy import subject_ref


def test_discover_reference_connectors():
    reg = ConnectorRegistry()
    # discover importuje moduły; rejestracja idzie do globalnego rejestru pakietu,
    # więc tu sprawdzamy, że import się udał bez błędów.
    reg.discover("osint_connectors.connectors")
    assert reg.load_errors == []
    from osint_connectors import registry as global_reg
    assert "manual_confirm" in global_reg.names()
    assert "passive_local_dataset" in global_reg.names()


def test_manual_returns_unknown():
    import osint_connectors.connectors.manual  # noqa: F401  (rejestruje konektor)
    from osint_connectors import registry
    c = registry.get("manual_confirm")
    f = asyncio.run(run([c], Subject(InputKind.EMAIL, "a@b.c"), Context(salt="s")))[0]
    assert f.status == Status.UNKNOWN
    assert f.error_kind == "manual_required"


def test_passive_found_and_not_found():
    import osint_connectors.connectors.passive_local  # noqa: F401
    from osint_connectors import registry
    c = registry.get("passive_local_dataset")
    subj = Subject(InputKind.EMAIL, "known@example.com")
    ref = subject_ref(subj, "s")
    ctx_hit = Context(salt="s", dataset={"known_refs": {ref}})
    ctx_miss = Context(salt="s", dataset={"known_refs": set()})
    hit = asyncio.run(run([c], subj, ctx_hit))[0]
    miss = asyncio.run(run([c], subj, ctx_miss))[0]
    assert hit.status == Status.FOUND and hit.confidence == 1.0
    assert miss.status == Status.NOT_FOUND and miss.confidence < 1.0


def test_passive_no_dataset_is_unknown():
    import osint_connectors.connectors.passive_local  # noqa: F401
    from osint_connectors import registry
    c = registry.get("passive_local_dataset")
    f = asyncio.run(run([c], Subject(InputKind.EMAIL, "x@y.z"), Context(salt="s")))[0]
    assert f.status == Status.UNKNOWN and f.error_kind == "no_dataset"

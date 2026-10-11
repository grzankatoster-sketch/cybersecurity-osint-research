"""Testy modelu wyniku i haszowania celu."""
import pytest

from osint_connectors import Finding, InputKind, SourceKind, Status, Subject, subject_ref


def test_subject_validation():
    with pytest.raises(ValueError):
        Subject(InputKind.EMAIL, "   ")


def test_finding_confidence_range():
    with pytest.raises(ValueError):
        Finding("c", SourceKind.PASSIVE, Status.FOUND, 1.5, "ref")


def test_error_status_forces_error_kind():
    f = Finding("c", SourceKind.PASSIVE, Status.ERROR, 0.0, "ref")
    assert f.error_kind == "unspecified"
    u = Finding("c", SourceKind.PASSIVE, Status.UNKNOWN, 0.0, "ref")
    assert u.error_kind == "unspecified"


def test_found_does_not_force_error_kind():
    f = Finding("c", SourceKind.PASSIVE, Status.FOUND, 1.0, "ref")
    assert f.error_kind is None


def test_to_dict_deterministic_and_no_raw_subject():
    f = Finding("c", SourceKind.PASSIVE, Status.FOUND, 0.912345, "refhash")
    d = f.to_dict()
    assert d["confidence"] == 0.9123
    assert d["status"] == "found"
    assert d["source"] == "passive"
    assert "refhash" == d["subject_ref"]


def test_subject_ref_stable_and_salted():
    s = Subject(InputKind.EMAIL, "  Jan.Kowalski@Example.COM ")
    r1 = subject_ref(s, "sol-sprawy-1")
    r2 = subject_ref(Subject(InputKind.EMAIL, "jan.kowalski@example.com"), "sol-sprawy-1")
    assert r1 == r2  # normalizacja trim+lower
    assert r1 != subject_ref(s, "inna-sol")  # sól zmienia hash
    assert "example.com" not in r1  # brak surowej wartości
    assert len(r1) == 64  # sha256 hex


def test_subject_ref_requires_salt():
    with pytest.raises(ValueError):
        subject_ref(Subject(InputKind.EMAIL, "a@b.c"), "")

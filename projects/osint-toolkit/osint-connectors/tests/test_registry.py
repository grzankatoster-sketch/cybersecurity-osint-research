"""Testy rejestru i izolowanego odkrywania konektorów."""
import os
import sys
import textwrap

import pytest

from osint_connectors import InputKind, SourceKind
from osint_connectors.connector import ConnectorRegistry
from osint_connectors.model import Finding, Status, Subject


class _Good:
    name = "good"
    source_kind = SourceKind.PASSIVE
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        return Finding(self.name, self.source_kind, Status.NOT_FOUND, 0.9, "ref")


def test_register_and_duplicate():
    reg = ConnectorRegistry()
    reg.register(_Good())
    assert reg.names() == ["good"]
    with pytest.raises(ValueError):
        reg.register(_Good())


def test_for_input_filter():
    reg = ConnectorRegistry()
    reg.register(_Good())
    assert reg.for_input(InputKind.EMAIL)
    assert reg.for_input(InputKind.USERNAME) == []


def test_protocol_rejects_non_connector():
    reg = ConnectorRegistry()

    class Bad:
        name = "bad"
        source_kind = SourceKind.PASSIVE
        supported_inputs = frozenset()
        # brak metody check -> nie spełnia Protocol

    with pytest.raises(TypeError):
        reg.register(Bad())


def test_discover_isolates_broken_module(tmp_path):
    pkg = tmp_path / "tmp_conn_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "ok_mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (pkg / "broken_mod.py").write_text("def x(:\n pass\n", encoding="utf-8")
    sys.path.insert(0, str(tmp_path))
    try:
        reg = ConnectorRegistry()
        reg.discover("tmp_conn_pkg")  # nie może rzucić mimo broken_mod
    finally:
        sys.path.remove(str(tmp_path))
        for m in list(sys.modules):
            if m.startswith("tmp_conn_pkg"):
                del sys.modules[m]
    assert any("broken_mod" in e for e in reg.load_errors)

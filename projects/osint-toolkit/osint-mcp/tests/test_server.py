"""Warstwa MCP: lista narzędzi, opisy zakresu i przejście przez FastMCP z fałszywym podprocesem."""

import asyncio
import json
import subprocess

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from conftest import FakeRun
from osint_mcp import server

EXPECTED = {"dns_audit", "phone_check", "hibp_domain_breaches", "ip_info", "rdap", "subdomains"}


def list_tools():
    return asyncio.run(server.mcp.list_tools())


def test_exactly_the_defensive_tools_are_exposed():
    names = {t.name for t in list_tools()}
    assert names == EXPECTED
    # nic person-oriented
    assert not any(bad in n for n in names for bad in ("username", "entity", "person", "email", "graph", "osoba"))


def test_every_tool_states_defensive_scope():
    for t in list_tools():
        text = (t.description or "").lower()
        assert "zakres defensywny" in text, t.name
        assert "nie służy do wyszukiwania osób" in text, t.name


def test_input_schemas():
    schemas = {t.name: t.inputSchema for t in list_tools()}
    assert schemas["phone_check"]["required"] == ["number"]
    assert schemas["phone_check"]["properties"]["region"]["default"] == "PL"
    for name in EXPECTED - {"phone_check", "ip_info"}:
        assert schemas[name]["required"] == ["domain"]
    assert schemas["ip_info"]["required"] == ["ip"]


def test_call_tool_end_to_end_with_fake_subprocess(fake_root, monkeypatch):
    run = FakeRun(stdout=json.dumps({"status": "ok", "result": {"count": 3}}))
    monkeypatch.setattr(subprocess, "run", run)
    content, structured = asyncio.run(server.mcp.call_tool("subdomains", {"domain": "example.com"}))
    assert structured == {"status": "ok", "result": {"count": 3}}
    assert '"count": 3' in content[0].text.replace('":3', '": 3')
    assert run.calls[0][0][1:4] == ["-m", "net_intel", "subdomains"]


def test_tool_failure_surfaces_as_tool_error(tmp_path, monkeypatch):
    from osint_mcp import runner
    monkeypatch.setattr(runner, "ROOT", tmp_path)  # brak .venv
    with pytest.raises(ToolError) as ei:
        asyncio.run(server.mcp.call_tool("dns_audit", {"domain": "example.com"}))
    assert "START_DNS_AUDIT.cmd" in str(ei.value)


def test_invalid_input_surfaces_as_tool_error():
    with pytest.raises(ToolError) as ei:
        asyncio.run(server.mcp.call_tool("rdap", {"domain": "--version"}))
    assert "'-'" in str(ei.value)

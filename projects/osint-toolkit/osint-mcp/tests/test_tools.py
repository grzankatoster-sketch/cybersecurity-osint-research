import json
import subprocess
from pathlib import Path

import pytest

from conftest import FakeRun
from osint_mcp import runner, tools
from osint_mcp.runner import ToolFailure, valid_domain, valid_ip, valid_phone, valid_region


# --- walidacja wejścia -------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["example.com", "sub.example.co.uk", "xn--zaol-hqa.pl", "zażółć.pl", "a-b.example.com"])
def test_valid_domain_ok(value):
    assert valid_domain(value) == value


@pytest.mark.parametrize("value", [
    "", "   ", "-evil.com", "--version", "-d example.com", "example", "a..b.com", "https://example.com",
    "example.com/path", "user@example.com", "example.com:443", "exa mple.com", "example.com\nrm -rf",
    "example.com;ls", "$(whoami).com", "x" * 254, ".example.com", "example.com.-", 123, None,
])
def test_valid_domain_rejects(value):
    with pytest.raises(ToolFailure):
        valid_domain(value)


@pytest.mark.parametrize("value,expected", [("8.8.8.8", "8.8.8.8"), (" 2001:4860:4860::8888 ", "2001:4860:4860::8888"),
                                            ("2001:DB8::A", "2001:db8::a")])
def test_valid_ip_ok(value, expected):
    assert valid_ip(value) == expected


@pytest.mark.parametrize("value", ["", "-1", "--help", "999.1.1.1", "8.8.8.8/32", "example.com", "1.2.3.4; id", "1.2.3.4\n5"])
def test_valid_ip_rejects(value):
    with pytest.raises(ToolFailure):
        valid_ip(value)


@pytest.mark.parametrize("value", ["+48 600 100 200", "600100200", "(22) 123-45-67", "+1.555.0100"])
def test_valid_phone_ok(value):
    assert valid_phone(value) == value


@pytest.mark.parametrize("value", ["", "-48600100200", "--help", "abc", "+48 600; rm", "6" * 41, "+", "12"])
def test_valid_phone_rejects(value):
    with pytest.raises(ToolFailure):
        valid_phone(value)


def test_valid_region():
    assert valid_region("pl") == "PL"
    for bad in ("", "POL", "-p", "1a", "P"):
        with pytest.raises(ToolFailure):
            valid_region(bad)


# --- kontrakt podprocesu -----------------------------------------------------------------------

def test_dns_audit_command_and_json_parsing(fake_root):
    run = FakeRun(stdout=json.dumps({"domain": "example.com", "counts": {"FAIL": 0}}))
    out = tools.dns_audit("example.com", run=run)
    assert out == {"domain": "example.com", "counts": {"FAIL": 0}}
    cmd, kw = run.calls[0]
    assert cmd[0] == str(fake_root / "dns-audit" / ".venv" / "Scripts" / "python.exe")
    assert cmd[1:] == ["-m", "dns_audit", "example.com", "--json"]
    assert kw["timeout"] > 0 and "shell" not in kw and kw["capture_output"] is True
    assert kw["stdin"] is subprocess.DEVNULL  # nie dziedziczy stdin serwera MCP (kanał protokołu)
    assert kw["env"]["PYTHONPATH"].startswith(str(fake_root / "dns-audit" / "src"))
    assert kw["env"]["PYTHONUTF8"] == "1"


def test_net_intel_commands(fake_root):
    run = FakeRun(stdout="{}")
    tools.ip_info("8.8.8.8", run=run)
    tools.rdap("example.com", run=run)
    tools.subdomains("example.com", run=run)
    argv = [c[0][2:] for c in run.calls]
    assert argv == [["net_intel", "ip", "8.8.8.8", "--json"],
                    ["net_intel", "rdap", "example.com", "--json"],
                    ["net_intel", "subdomains", "example.com", "--json"]]
    assert all(c[0][0].endswith("python.exe") and "net-intel" in c[0][0] for c in run.calls)


def test_hibp_command_no_save_and_isolated_cwd(fake_root):
    run = FakeRun(stdout=json.dumps({"domains": []}))
    out = tools.hibp_domain_breaches("adobe.com", run=run)
    cmd, kw = run.calls[0]
    assert out == {"domains": []}
    assert cmd[1:] == ["-m", "hibp_monitor", "breaches", "--domain", "adobe.com", "--no-save", "--json"]
    assert Path(kw["cwd"]).name.startswith("osint-mcp-")  # katalog tymczasowy, nie repo (brak state.json)


def test_phone_check_reads_json_file_and_unwraps_list(fake_root):
    info = {"input": "+48 600 100 200", "valid": True, "e164": "+48600100200"}
    run = FakeRun(stdout="tekst dla ludzi", json_file_content=json.dumps([info]))
    out = tools.phone_check("+48 600 100 200", "pl", run=run)
    assert out == info
    cmd, kw = run.calls[0]
    assert cmd[1:5] == ["-m", "phone_check", "+48 600 100 200", "--region"] and cmd[5] == "PL"
    assert cmd[6] == "--json" and Path(cmd[7]).name == "phone.json"
    assert not Path(cmd[7]).exists()  # katalog tymczasowy posprzątany
    assert "--dorks" not in cmd


def test_phone_check_invalid_number_exit_1_still_returns_json(fake_root):
    run = FakeRun(returncode=1, json_file_content=json.dumps([{"valid": False, "error": "za krótki"}]))
    assert tools.phone_check("123456", run=run) == {"valid": False, "error": "za krótki"}


def test_findings_exit_code_1_still_returns_json(fake_root):
    run = FakeRun(stdout=json.dumps({"status": "failed"}), returncode=1)
    assert tools.subdomains("example.com", run=run) == {"status": "failed"}


def test_list_result_is_wrapped(fake_root):
    assert tools.dns_audit("example.com", run=FakeRun(stdout="[1, 2]")) == {"result": [1, 2]}


def test_invalid_input_never_spawns_process(fake_root):
    run = FakeRun()
    for call in (lambda: tools.dns_audit("--version", run=run), lambda: tools.rdap("-x.com", run=run),
                 lambda: tools.ip_info("not-an-ip", run=run), lambda: tools.subdomains("a b.com", run=run),
                 lambda: tools.hibp_domain_breaches("-h", run=run), lambda: tools.phone_check("-1234567", run=run),
                 lambda: tools.phone_check("123456789", "--x", run=run)):
        with pytest.raises(ToolFailure):
            call()
    assert run.calls == []


# --- błędy -------------------------------------------------------------------------------------

@pytest.mark.parametrize("fn,arg,start,folder", [
    (tools.dns_audit, "example.com", "START_DNS_AUDIT.cmd", "dns-audit"),
    (tools.hibp_domain_breaches, "example.com", "START_HIBP_MONITOR.cmd", "hibp-monitor"),
    (tools.phone_check, "+48600100200", "START_PHONE_CHECK.cmd", "phone-check"),
    (tools.rdap, "example.com", "START_NET_INTEL.cmd", "net-intel"),
    (tools.ip_info, "8.8.8.8", "START_NET_INTEL.cmd", "net-intel"),
    (tools.subdomains, "example.com", "START_NET_INTEL.cmd", "net-intel"),
])
def test_missing_venv_names_the_start_script(tmp_path, monkeypatch, fn, arg, start, folder):
    monkeypatch.setattr(runner, "ROOT", tmp_path)  # puste drzewo: brak .venv
    run = FakeRun()
    with pytest.raises(ToolFailure) as ei:
        fn(arg, run=run)
    msg = str(ei.value)
    assert start in msg and folder in msg and ".venv" in msg
    assert run.calls == []


def test_start_scripts_exist_in_repo():
    """Nazwy START_*.cmd z komunikatów muszą istnieć obok modułów (o ile moduły są w repo)."""
    repo = Path(__file__).resolve().parents[2]
    for mod in runner.MODULES.values():
        if (repo / mod.folder).is_dir():
            assert (repo / mod.folder / mod.start).is_file(), mod.start


def test_timeout(fake_root):
    run = FakeRun(exc=subprocess.TimeoutExpired(cmd="x", timeout=5))
    with pytest.raises(ToolFailure, match="limit czasu"):
        tools.dns_audit("example.com", run=run)


def test_cannot_start_process(fake_root):
    with pytest.raises(ToolFailure, match="nie można uruchomić"):
        tools.dns_audit("example.com", run=FakeRun(exc=OSError("brak pliku")))


@pytest.mark.parametrize("stdout", ["", "Audyt DNS: tekst zamiast JSON", "{niepelny"])
def test_garbage_output_is_error_not_empty_result(fake_root, stdout):
    with pytest.raises(ToolFailure, match="poprawnego JSON"):
        tools.dns_audit("example.com", run=FakeRun(stdout=stdout))


def test_usage_or_network_exit_code_is_error_with_stderr_tail(fake_root):
    run = FakeRun(stdout="{}", stderr="Traceback...\nBłąd sieci: timeout", returncode=3)
    with pytest.raises(ToolFailure) as ei:
        tools.hibp_domain_breaches("example.com", run=run)
    assert "kodem 3" in str(ei.value) and "Błąd sieci: timeout" in str(ei.value)


def test_phone_missing_result_file_is_error(fake_root):
    with pytest.raises(ToolFailure, match="nie zapisał"):
        tools.phone_check("+48600100200", run=FakeRun(stdout=""))


def test_oversized_output_rejected(fake_root, monkeypatch):
    monkeypatch.setattr(runner, "MAX_OUTPUT_BYTES", 10)
    with pytest.raises(ToolFailure, match="limit rozmiaru"):
        tools.dns_audit("example.com", run=FakeRun(stdout=json.dumps({"a": "x" * 100})))


# --- OPEN-06: srodowisko podprocesow ------------------------------------------------------------

SYNTH = "SYNTH-host-secret-0000"


@pytest.mark.parametrize(
    ("fn", "arg", "own", "foreign"),
    [
        (tools.dns_audit, "example.com", "OSINT_PROXY", "IPINFO_TOKEN"),
        (tools.ip_info, "192.0.2.1", "IPINFO_TOKEN", "OSINT_PROXY"),
    ],
)
def test_subprocess_env_is_an_allowlist(fake_root, monkeypatch, fn, arg, own, foreign):
    for key in ("AWS_SECRET_ACCESS_KEY", "HIBP_API_KEY", "BRAVE_SEARCH_API_KEY", "GITHUB_TOKEN", own, foreign):
        monkeypatch.setenv(key, SYNTH)
    monkeypatch.setenv("HTTPS_PROXY", "socks5h://127.0.0.1:9150")
    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")
    run = FakeRun(stdout="{}")
    fn(arg, run=run)
    env = run.calls[0][1]["env"]
    assert env[own] == SYNTH
    for key in ("AWS_SECRET_ACCESS_KEY", "HIBP_API_KEY", "BRAVE_SEARCH_API_KEY", "GITHUB_TOKEN", foreign):
        assert key not in env
    assert env["HTTPS_PROXY"] == "socks5h://127.0.0.1:9150"  # routing kept: no silent direct traffic
    assert "/somewhere/else" not in env["PYTHONPATH"]
    assert "PATH" in {k.upper() for k in env}


def test_hibp_catalog_call_gets_no_api_key(fake_root, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", SYNTH)
    run = FakeRun(stdout="{}")
    tools.hibp_domain_breaches("example.com", run=run)
    assert "HIBP_API_KEY" not in run.calls[0][1]["env"]

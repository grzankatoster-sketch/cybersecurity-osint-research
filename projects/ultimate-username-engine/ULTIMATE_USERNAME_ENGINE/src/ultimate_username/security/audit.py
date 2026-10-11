"""Audit orchestration: tool-optional scanners + built-in offline checks.

External scanners (bandit, pip-audit) are run when importable, skipped
otherwise - the spec requires choosing the right tools, not every tool. The
proxy validation and secrets scan are built in and always run.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ultimate_username.opsec.config import ProxyConfig
from ultimate_username.opsec.policy import EgressPolicy
from ultimate_username.opsec.server import ForwardProxy
from ultimate_username.security.secrets import scan as scan_secrets

ROOT = Path(__file__).resolve().parents[3]


@dataclass(slots=True)
class Check:
    name: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""


@dataclass(slots=True)
class AuditResult:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status == "FAIL"]


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _const_resolver(ip: str) -> Callable[[str], list[str]]:
    return lambda host: [ip]


def _run_tool(args: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=300, cwd=ROOT)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout + proc.stderr)[-4000:]


def validate_proxy() -> AuditResult:
    """Offline proxy/policy checks - deterministic, no network."""

    result = AuditResult()
    secure = EgressPolicy(
        allowed_hosts=frozenset({"api.github.com"}), allowed_ports=frozenset({443})
    )

    deny_default = EgressPolicy(require_allowlist=True)
    d = deny_default.check_target("api.github.com", 443, lambda h: ["140.82.121.6"])
    result.add("allowlist-deny-by-default", "PASS" if not d.allowed else "FAIL", d.reason)

    d = secure.check_target("evil.example.com", 443, lambda h: ["140.82.121.6"])
    result.add("allowlist-blocks-unlisted-host", "PASS" if not d.allowed else "FAIL", d.reason)

    ssrf_cases = (
        ("metadata", "169.254.169.254"),
        ("private", "10.0.0.1"),
        ("loopback", "127.0.0.1"),
    )
    for label, ip in ssrf_cases:
        permissive = EgressPolicy(require_allowlist=False, allowed_ports=frozenset())
        d = permissive.check_target("x.example.com", 443, _const_resolver(ip))
        result.add(f"ssrf-blocks-{label}", "PASS" if not d.allowed else "FAIL", d.reason)

    # nosec B104 - we deliberately assert that a 0.0.0.0 bind is REJECTED.
    bad = ProxyConfig(bind_host="0.0.0.0", allowed_hosts=frozenset({"x.com"}))  # nosec B104
    result.add(
        "refuses-open-proxy-without-auth",
        "PASS" if any("open proxy" in p for p in bad.validate()) else "FAIL",
    )

    failclosed = ProxyConfig(fail_closed=True, require_allowlist=True, allowed_hosts=frozenset())
    result.add(
        "fail-closed-empty-allowlist",
        "PASS" if any("denies all" in p for p in failclosed.validate()) else "FAIL",
    )

    # Live smoke: the server must bind on loopback and deny a disallowed CONNECT.
    try:
        status = asyncio.run(_smoke_denied())
        result.add(
            "server-denies-disallowed-connect",
            "PASS" if status == 403 else "FAIL",
            f"status={status}",
        )
    except Exception as exc:  # noqa: BLE001 - smoke failure is a finding
        result.add("server-denies-disallowed-connect", "FAIL", f"{type(exc).__name__}: {exc}")
    return result


async def _smoke_denied() -> int:
    proxy = ForwardProxy(
        ProxyConfig(bind_port=0, allowed_hosts=frozenset({"example.com"})),
        policy=EgressPolicy(
            allowed_hosts=frozenset({"example.com"}), allowed_ports=frozenset({443})
        ),
        resolver=lambda h: ["140.82.121.6"],
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        await writer.drain()
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        writer.close()
        parts = header.split(b" ")
        return int(parts[1]) if len(parts) > 1 else 0
    finally:
        await proxy.stop()


def run_audit() -> AuditResult:
    result = validate_proxy()

    findings = scan_secrets(ROOT)
    if findings:
        detail = "; ".join(f"{f.path}:{f.line} ({f.rule})" for f in findings[:10])
        result.add("secrets-scan", "FAIL", detail)
    else:
        result.add("secrets-scan", "PASS", "no secrets in tracked files")

    if _module_available("bandit"):
        code, out = _run_tool([sys.executable, "-m", "bandit", "-r", "src", "-q", "-ll"])
        result.add("bandit", "PASS" if code == 0 else "FAIL", out[-800:])
    else:
        result.add("bandit", "SKIP", "bandit not installed (pip install bandit)")

    if _module_available("pip_audit"):
        code, out = _run_tool([sys.executable, "-m", "pip_audit", "-s", "osv"])
        result.add("pip-audit", "PASS" if code == 0 else "FAIL", out[-800:])
    else:
        result.add("pip-audit", "SKIP", "pip-audit not installed (pip install pip-audit)")

    return result


def write_report(result: AuditResult, path: Path) -> None:
    payload = {
        "summary": {
            "pass": sum(c.status == "PASS" for c in result.checks),
            "fail": sum(c.status == "FAIL" for c in result.checks),
            "skip": sum(c.status == "SKIP" for c in result.checks),
        },
        "checks": [asdict(c) for c in result.checks],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

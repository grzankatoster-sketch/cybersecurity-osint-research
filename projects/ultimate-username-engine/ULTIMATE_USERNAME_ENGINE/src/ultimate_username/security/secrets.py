"""Built-in secrets scan over git-tracked files (no external tool required).

The fallback when gitleaks is not installed. It scans the working tree of the
tracked files only (no git history - that is gitleaks' job, see ``audit.py``).
Exclusions are by path segment, never by substring (``latest_config.txt`` is
scanned; ``tests/`` and ``test_*.py`` are not), and obvious placeholders
(``YOUR_API_KEY_HERE``, ``changeme``) are not findings (R5-09).
"""

# Imported unchanged from the unmerged hardening branch so that `python -m ultimate_username.security`
# (audit.py) has its built-in scanner; see docs/SECURITY_REVIEW.md (OPEN-05).

from __future__ import annotations

import re
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_ASSIGN_NAME = r"(?:secret|password|passwd|api[_-]?key|access[_-]?key|token)"
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "private-key-block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    ),
    ("stripe-live-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    (
        "openai-key",
        re.compile(
            r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"
            r"|[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})"
        ),
    ),
    (
        "bearer-assignment",
        re.compile(rf"(?i){_ASSIGN_NAME}\w*\s*[:=]\s*['\"](?P<value>[^'\"]{{8,}})['\"]"),
    ),
    (
        "env-assignment",
        re.compile(
            r"^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY)"
            r"[A-Z0-9_]*\s*=\s*(?P<value>[^\s'\"#]{8,})\s*$"
        ),
    ),
    (
        "url-credentials",
        re.compile(
            r"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"<>]+:(?P<value>[^/\s@'\"<>]{3,})@[\w.\-\[\]]+"
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b")),
)

# Out of scope: tests/examples/fixtures, generated captures of third-party pages
# (artifacts/, .body, .html) which hold foreign content, and environments/caches.
_SKIP_SEGMENTS = frozenset(
    {
        "tests",
        "test",
        "fixtures",
        "examples",
        "artifacts",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".git",
    }
)
_SKIP_SUFFIXES = (".body", ".html", ".htm", ".xml", ".zip", ".png", ".jpg", ".gif", ".pdf")
_MAX_BYTES = 20 * 1024 * 1024
_PLACEHOLDER_HINTS = (
    "your",
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "dummy",
    "redacted",
    "xxxx",
    "****",
)
# Whole-value template shapes: ${VAR}, $VAR, %(name)s, {{ var }}, <password>, {secret}.
_TEMPLATE = re.compile(r"^(?:\$\{?[A-Za-z_]\w*\}?|%\(\w+\)s|\{\{.*\}\}|<[^<>]+>|\{[^{}]+\})$")


@dataclass(frozen=True, slots=True)
class SecretFinding:
    path: str
    line: int
    rule: str


def _tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(  # nosec B603 B607
            ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [line for line in out.stdout.splitlines() if line]


def _skipped(norm: str) -> bool:
    path = PurePosixPath(norm)
    if any(part in _SKIP_SEGMENTS for part in path.parts[:-1]):
        return True
    # Saved third-party READMEs/FAQs of the OSINT audits (audyt_*/sources/): foreign text.
    if path.parts[0].startswith("audyt_") and "sources" in path.parts[1:-1]:
        return True
    name = path.name.lower()
    if name.startswith("test_") or name == "conftest.py" or ".example" in name:
        return True
    return name.endswith(_SKIP_SUFFIXES)


def _placeholder(value: str) -> bool:
    # Only whole-value shapes and explicit words: a real secret may contain $, <, { ...
    if _TEMPLATE.match(value):
        return True
    lowered = value.lower()
    if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
        return True
    return len(set(lowered)) <= 2  # "aaaaaaaa", "********", "x-x-x-x"


def scan_text(text: str, path: str = "<text>") -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in _PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            value = match.groupdict().get("value")
            if value is not None and _placeholder(value):
                continue
            findings.append(SecretFinding(path, lineno, rule))
    return findings


def scan(root: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for rel in _tracked_files(root):
        norm = rel.replace("\\", "/")
        if _skipped(norm):
            continue
        path = root / rel
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text("utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_text(text, norm))
    return findings

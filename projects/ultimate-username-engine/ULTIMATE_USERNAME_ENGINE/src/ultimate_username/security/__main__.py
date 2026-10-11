"""CLI entry point for the security automation module."""

from __future__ import annotations

import argparse
import sys

from ultimate_username.security.audit import (
    ROOT,
    AuditResult,
    run_audit,
    validate_proxy,
    write_report,
)


def _print(result: AuditResult) -> None:
    icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[skip]"}  # nosec B105 - UI labels
    for check in result.checks:
        line = f"{icon.get(check.status, '[?]')} {check.name}"
        if check.detail:
            line += f" - {check.detail.splitlines()[0][:120]}"
        print(line)
    print(
        f"\n{sum(c.status == 'PASS' for c in result.checks)} pass, "
        f"{len(result.failed)} fail, "
        f"{sum(c.status == 'SKIP' for c in result.checks)} skip"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ultimate_username.security")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit", help="run the full security audit")
    sub.add_parser("test-proxy", help="offline proxy/policy validation")
    args = parser.parse_args(argv)

    if args.command == "audit":
        result = run_audit()
        write_report(result, ROOT / "artifacts" / "security-audit.json")
    else:
        result = validate_proxy()
        write_report(result, ROOT / "artifacts" / "proxy-validation.json")

    _print(result)
    return 1 if result.failed else 0


if __name__ == "__main__":
    sys.exit(main())

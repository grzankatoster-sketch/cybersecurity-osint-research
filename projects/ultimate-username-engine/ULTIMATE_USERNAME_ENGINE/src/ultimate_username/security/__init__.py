"""Repeatable security automation for the OSINT engine.

``python -m ultimate_username.security audit``       - full audit (scanners + checks)
``python -m ultimate_username.security test-proxy``   - offline proxy/policy validation
"""

from __future__ import annotations

from ultimate_username.security.audit import AuditResult, run_audit, validate_proxy, write_report

__all__ = ["AuditResult", "run_audit", "validate_proxy", "write_report"]

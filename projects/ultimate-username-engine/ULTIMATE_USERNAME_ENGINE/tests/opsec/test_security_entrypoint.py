"""OPEN-05 regression: the security audit entry point imports and its offline checks run."""

from __future__ import annotations

import importlib

from ultimate_username.security.audit import validate_proxy
from ultimate_username.security.secrets import scan_text


def test_entry_point_imports() -> None:
    module = importlib.import_module("ultimate_username.security.__main__")
    assert callable(module.main)


def test_builtin_scanner_flags_key_shapes_and_skips_placeholders() -> None:
    fake_aws = "AKIA" + "Q" * 8 + "7" * 8  # built at runtime: not a literal secret in the repo
    assert [f.rule for f in scan_text(f"key = {fake_aws}", "x.py")] == ["aws-access-key"]
    assert scan_text('api_key = "YOUR_API_KEY_HERE"', "x.py") == []


def test_offline_proxy_validation_passes() -> None:
    result = validate_proxy()
    assert result.checks and not result.failed

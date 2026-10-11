"""Read-only execution of built-in donor extraction, without optional CLI imports."""

import ast
import importlib
import logging
import os
import socket
import sys
import types
from pathlib import Path

# Donor sources (01_nazwa_uzytkownika) live outside the repo; set UEE_DONOR_ROOT to their directory.
BASE = Path(os.environ.get("UEE_DONOR_ROOT", "UEE_DONOR_ROOT-not-set"))


def load():
    sys.dont_write_bytecode = True
    package = types.ModuleType("socid_extractor")
    package.__path__ = [str(BASE / "socid_extractor" / "socid_extractor")]
    sys.modules["socid_extractor"] = package
    plugins = importlib.import_module("socid_extractor.plugins")
    plugins.load_plugins = lambda schemes: None  # explicit built-ins-only audit
    main = importlib.import_module("socid_extractor.main")
    # Exact Maigret wrapper function; not a claim of running its complete CLI.
    source = BASE / "maigret" / "maigret" / "checking.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "extract_ids_data"
    )
    namespace = {"extract": main.extract, "logging": logging, "Dict": dict, "Any": object}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    return main, namespace["extract_ids_data"]


def deny_network(*args, **kwargs):
    raise RuntimeError("Donor runtime network disabled")


def guard():
    socket.create_connection = deny_network
    socket.socket.connect = deny_network
    socket.getaddrinfo = deny_network

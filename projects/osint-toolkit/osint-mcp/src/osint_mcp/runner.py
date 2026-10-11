"""Uruchamianie modułów repo jako PODPROCESÓW z ich własnych .venv (jak panel/app.py).

Argumenty zawsze jako lista (bez powłoki), twardy timeout, wynik to sparsowany JSON.
Walidacja wejścia odrzuca m.in. argumenty zaczynające się od "-" (wstrzyknięcie opcji CLI).
Stdout serwera MCP (stdio) jest kanałem protokołu: ten moduł niczego nie drukuje.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(os.environ.get("OSINT_ROOT") or Path(__file__).resolve().parents[3])
MAX_OUTPUT_BYTES = 20 * 1024 * 1024
OK_EXIT_CODES = (0, 1)  # 1 = ustalenia / numer niepoprawny / wynik niepełny: JSON jest nadal wiarygodny


class ToolFailure(Exception):
    """Błąd narzędzia (wejście, brak .venv, timeout, awaria modułu). Komunikat jest bezpieczny do pokazania."""


@dataclass(frozen=True)
class Module:
    folder: str
    package: str
    start: str


MODULES = {
    "dns-audit": Module("dns-audit", "dns_audit", "START_DNS_AUDIT.cmd"),
    "phone-check": Module("phone-check", "phone_check", "START_PHONE_CHECK.cmd"),
    "hibp-monitor": Module("hibp-monitor", "hibp_monitor", "START_HIBP_MONITOR.cmd"),
    "net-intel": Module("net-intel", "net_intel", "START_NET_INTEL.cmd"),
}

# --- walidacja wejścia -------------------------------------------------------------------------

_DOMAIN_RE = re.compile(r"^[^\W_](?:[\w.-]*[^\W_])?$")  # litery/cyfry (też IDN), kropki, myślniki; bez / @ : spacji
_PHONE_RE = re.compile(r"^\+?[0-9(][0-9 ().-]{2,38}$")


def _clean(value: object, name: str, maxlen: int) -> str:
    if not isinstance(value, str):
        raise ToolFailure(f"pole {name} musi być tekstem")
    val = value.strip()
    if not val:
        raise ToolFailure(f"brak pola: {name}")
    if len(val) > maxlen or "\n" in val or "\r" in val or "\x00" in val:
        raise ToolFailure(f"nieprawidłowe pole: {name}")
    if val.startswith("-"):
        raise ToolFailure(f"pole {name} nie może zaczynać się od '-'")
    return val


def valid_domain(value: object) -> str:
    """Sama nazwa domeny (bez schematu, ścieżki, adresu e-mail, portu)."""
    val = _clean(value, "domain", 253)
    if ".." in val or "." not in val or not _DOMAIN_RE.match(val):
        raise ToolFailure(f"nieprawidłowa domena: {val!r} (podaj samą nazwę, np. example.com)")
    return val


def valid_ip(value: object) -> str:
    val = _clean(value, "ip", 45)
    try:
        return str(ipaddress.ip_address(val))
    except ValueError:
        raise ToolFailure(f"nieprawidłowy adres IP: {val!r}") from None


def valid_phone(value: object) -> str:
    val = _clean(value, "number", 40)
    if not _PHONE_RE.match(val):
        raise ToolFailure("number: cyfry z opcjonalnym '+' na początku oraz spacjami, nawiasami, '.' i '-'")
    return val


def valid_region(value: object) -> str:
    val = _clean(value, "region", 2).upper()
    if not re.fullmatch(r"[A-Z]{2}", val):
        raise ToolFailure("region: dwuliterowy kod ISO kraju, np. PL")
    return val


# --- uruchamianie ------------------------------------------------------------------------------

# Srodowisko podprocesu: lista dozwolonych zmiennych zamiast calego os.environ serwera MCP, zeby klucze
# i tokeny hosta (np. HIBP_API_KEY, klucze chmury) nie trafialy do modulow, ktore ich nie potrzebuja.
# Zmienne proxy zostaja: ich usuniecie przelaczyloby ruch na polaczenie bezposrednie (fail-open).
_BASE_ENV = frozenset({
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
})
# Zmienne czytane przez moduly w trybach wystawionych przez MCP (hibp-monitor: tylko katalog, bez klucza).
MODULE_ENV: dict[str, frozenset[str]] = {
    "dns-audit": frozenset({"OSINT_PROXY"}),
    "net-intel": frozenset({"IPINFO_TOKEN"}),
    "phone-check": frozenset(),
    "hibp-monitor": frozenset(),
}


def module_env(name: str, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Srodowisko dla modulu `name`: zmienne systemowe + jego wlasne, nic wiecej."""
    src = os.environ if base is None else base
    keep = _BASE_ENV | MODULE_ENV.get(name, frozenset())
    env = {k: v for k, v in src.items() if k.upper() in keep}
    env.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    return env


def module_python(module: Module, root: Path) -> Path:
    """Python z .venv modułu albo ToolFailure z informacją, który START_*.cmd uruchomić."""
    folder = root / module.folder
    for cand in (folder / ".venv" / "Scripts" / "python.exe", folder / ".venv" / "bin" / "python"):
        if cand.exists():
            return cand
    raise ToolFailure(
        f"Moduł {module.folder} nie ma środowiska .venv ({folder / '.venv'}). "
        f"Uruchom dwuklikiem {folder / module.start} (utworzy .venv i zainstaluje zależności), "
        "a potem ponów zapytanie."
    )


def _tail(text: str, limit: int = 400) -> str:
    lines = [ln.strip() for ln in (text or "").strip().splitlines() if ln.strip()]
    one = " | ".join(lines[-3:])
    return one if len(one) <= limit else one[-limit:]


def run_module(name: str, args: list[str], timeout: float, *, json_file: str | None = None,
               run: Callable | None = None, root: Path | None = None) -> object:
    """Uruchamia `python -m <pakiet> *args` w .venv modułu i zwraca sparsowany JSON.

    json_file: moduł zapisuje JSON do pliku (`--json PLIK`, np. phone-check) zamiast na stdout;
    plik powstaje w katalogu tymczasowym usuwanym po wywołaniu.
    """
    module = MODULES[name]
    root = root or ROOT
    run = run or subprocess.run  # wiązane przy wywołaniu (testy mogą podmienić subprocess.run)
    py = module_python(module, root)
    env = module_env(name)
    src = root / module.folder / "src"
    env["PYTHONPATH"] = str(src)
    with tempfile.TemporaryDirectory(prefix="osint-mcp-") as workdir:
        full_args = list(args)
        out_path = None
        if json_file:
            out_path = Path(workdir) / json_file
            full_args += ["--json", str(out_path)]
        cmd = [str(py), "-m", module.package, *full_args]
        try:
            # stdin=DEVNULL: podproces nie może dziedziczyć stdin serwera (to kanał protokołu MCP)
            proc = run(cmd, cwd=workdir, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ToolFailure(f"{name}: przekroczono limit czasu ({timeout:g} s)") from None
        except OSError as exc:
            raise ToolFailure(f"{name}: nie można uruchomić modułu: {exc}") from None
        stdout, stderr, code = proc.stdout or "", proc.stderr or "", proc.returncode
        if code not in OK_EXIT_CODES:
            detail = _tail(stderr) or _tail(stdout) or "brak komunikatu"
            raise ToolFailure(f"{name}: moduł zakończył się kodem {code}: {detail}")
        if out_path is not None:
            try:
                raw = out_path.read_text(encoding="utf-8")
            except OSError:
                raise ToolFailure(f"{name}: moduł nie zapisał wyniku JSON ({_tail(stderr) or 'brak komunikatu'})") from None
        else:
            raw = stdout
    if len(raw.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise ToolFailure(f"{name}: wynik przekracza limit rozmiaru ({MAX_OUTPUT_BYTES // (1024 * 1024)} MB)")
    try:
        return json.loads(raw)
    except ValueError:
        raise ToolFailure(f"{name}: moduł nie zwrócił poprawnego JSON-a ({_tail(raw or stderr, 160) or 'pusta odpowiedź'})") from None



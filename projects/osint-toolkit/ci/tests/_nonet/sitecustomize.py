"""Straznik sieci dla podprocesow testow E2E (ladowany automatycznie przez PYTHONPATH).

Kazda proba polaczenia (connect, connect_ex, create_connection, rozwiazanie nazwy) jest dopisywana do pliku
z zmiennej CI_NONET_LOG i konczy sie wyjatkiem. Test E2E sprawdza, ze plik dziennika jest pusty, wiec nawet
program, ktory polyka wyjatki sieciowe, nie ukryje proby polaczenia. Nie jest czescia zadnego pakietu."""

from __future__ import annotations

import os
import socket

_LOG = os.environ.get("CI_NONET_LOG")


def _note(kind: str, target: object) -> None:
    if _LOG:
        try:
            with open(_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"{kind} {target!r}\n")
        except OSError:
            pass


def _blocked(kind: str):
    def guard(*args, **_kwargs):
        _note(kind, args[1:2] if kind in ("connect", "connect_ex") else args[:2])
        raise OSError(f"CI: proba polaczenia sieciowego zablokowana ({kind})")

    return guard


if _LOG:
    socket.socket.connect = _blocked("connect")  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked("connect_ex")  # type: ignore[method-assign]
    socket.create_connection = _blocked("create_connection")  # type: ignore[assignment]
    socket.getaddrinfo = _blocked("getaddrinfo")  # type: ignore[assignment]

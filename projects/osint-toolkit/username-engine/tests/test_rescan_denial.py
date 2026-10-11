"""Regresja P1: ponawianie po odmowie dostępu / limicie i brak osłabienia TLS w kanale zapasowym.

Każdy test najpierw opisuje stare (błędne) zachowanie, które wykrywa, a przechodzi po poprawce.
Wszystko offline: `engine.scan` jest podmieniane atrapą, żaden Fetcher nie wychodzi do sieci.
"""
import asyncio

import pytest

from username_engine import cli
from username_engine import engine as ue
from username_engine.http import PROXY_DOWN
from username_engine.models import Result, Site, Status


class OfflineCtx:
    """Atrapa fabryki kanału: `OfflineCtx()` to async context manager (fetcher nieużywany — scan podmieniony)."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _site():
    return Site(name="synthetic", url="https://example.test/{username}")


def _err(http_status, reason):
    return Result("synthetic", "https://example.test/u", Status.ERROR, reason=reason, http_status=http_status)


def _run_rescan(initial, *, recovered=None, retries=1, with_fallback=True):
    """Uruchom rescan_errors z atrapą scan; zwróć (wynik, lista kanałów, które realnie odpytano)."""
    site = _site()
    channels = []

    async def fake_scan(username, sites, fetcher, control="auto", concurrency=50, on_result=None, channel="direct"):
        channels.append(channel)
        out = []
        for s in sites:
            r = recovered if recovered is not None else _err(initial[0].http_status, initial[0].reason)
            out.append(Result(s.name, "https://example.test/u", r.status, r.confidence, r.reason,
                              r.http_status, channel=channel))
        return out

    async def go():
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ue, "scan", fake_scan)
            return await ue.rescan_errors("synthetic", [site], initial, OfflineCtx,
                                          OfflineCtx if with_fallback else None, retries)

    return asyncio.run(go()), channels


# --- odmowa dostępu / limit / CAPTCHA: BRAK ponawiania (stare: oba szły przez proxy-retry i fallback) ---

@pytest.mark.parametrize("http_status,reason", [
    (403, "dostęp zabroniony (403)"),
    (401, "dostęp zabroniony (401)"),
    (429, "limit zapytań (429): serwis ograniczył zapytania, to nie dowodzi braku konta"),
    (200, "blokada anty-bot (challenge-platform)"),   # CAPTCHA zwraca zwykle 200/403 z treścią wyzwania
    (503, "błąd serwera (503)"),
])
def test_server_response_errors_not_retried(http_status, reason):
    result, channels = _run_rescan([_err(http_status, reason)])
    assert channels == [], f"odpowiedź serwera {http_status} nie może wywołać zmiany obwodu/proxy"
    assert result[0].status is Status.ERROR
    assert result[0].channel == "direct"   # tożsamość niezmieniona


# --- przejściowa awaria transportu: ponawiana (http_status is None) ---

def test_transient_transport_is_retried():
    recovered = Result("synthetic", "https://example.test/u", Status.FOUND, 0.9, "tekst obecności konta", 200)
    result, channels = _run_rescan([_err(None, "timeout")], recovered=recovered)
    assert "proxy-retry" in channels, "błąd transportu (brak odpowiedzi) ma być ponowiony na nowym obwodzie"
    assert result[0].status is Status.FOUND


def test_timeout_without_recovery_stays_error_not_notfound():
    result, channels = _run_rescan([_err(None, "timeout")])
    assert "proxy-retry" in channels
    assert result[0].status is Status.ERROR   # ERROR nigdy nie staje się NOT_FOUND


# --- martwe proxy: nie młotkujemy tego samego obwodu, ale próbujemy proxy zapasowego ---

def test_dead_proxy_skipped_on_retry_but_tried_on_fallback():
    result, channels = _run_rescan([_err(None, PROXY_DOWN + ": brak połączenia")])
    assert "proxy-retry" not in channels      # ten sam martwy obwód nie jest młotkowany
    assert "fallback" in channels             # drugie proxy wolno spróbować


# --- kanał zapasowy nie osłabia TLS ---

def test_retry_fetcher_through_proxy_has_no_insecure_retry():
    f = cli.retry_fetcher("socks5h://127.0.0.1:9050", strict_tls=False)
    # stare: fallback_fetcher przekazywał allow_insecure_retry=True -> pobieranie bez weryfikacji TLS przez proxy
    assert f.allow_insecure_retry is False

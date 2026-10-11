from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import FakeClient, FakeResolver, ForbiddenClient

from org_intel.hibp_catalog import (
    CATALOG_URL,
    MAX_ATTEMPTS,
    ConfigError,
    HibpCatalogClient,
)
from org_intel.http import NetworkError, Response
from org_intel.models import VerificationStatus, sha256_hex
from org_intel.verify import DohResolver, VerificationError, check, issue_token

# --- verify-domain ---------------------------------------------------------------------------


def test_wydanie_tokenu_zapisuje_tylko_hash(loaded):
    issued = issue_token(loaded, "https://www.Example.test/")
    dom = loaded.find_domain("example.test")
    assert dom.verification_status is VerificationStatus.PENDING
    assert issued.txt_record == f"org-intel-verification={issued.token}"
    assert issued.token in issued.instruction()
    record = loaded.verifications["example.test"]
    assert record["token_hash"] == sha256_hex(issued.token)
    loaded.save()
    assert issued.token not in loaded.path.read_text(encoding="utf-8")


def test_tokeny_sa_losowe(loaded):
    assert issue_token(loaded, "example.test").token != issue_token(loaded, "example.test").token


def test_check_sukces(loaded):
    issued = issue_token(loaded, "example.test")
    resolver = FakeResolver(["v=spf1 -all", f'"{issued.txt_record}"'])
    status = check(loaded, "example.test", resolver)
    assert status is VerificationStatus.VERIFIED
    dom = loaded.find_domain("example.test")
    assert dom.verified_at and resolver.calls == ["example.test"]


def test_check_brak_rekordu_failed_i_ponowienie(loaded):
    issued = issue_token(loaded, "example.test")
    assert check(loaded, "example.test", FakeResolver(["v=spf1 -all"])) is VerificationStatus.FAILED
    assert (
        check(loaded, "example.test", FakeResolver(["org-intel-verification=zly-token"])) is VerificationStatus.FAILED
    )
    assert loaded.find_domain("example.test").verified_at is None
    assert check(loaded, "example.test", FakeResolver([issued.txt_record])) is VerificationStatus.VERIFIED


def test_check_bez_tokenu_i_nieznana_domena(loaded):
    with pytest.raises(VerificationError, match="Brak wydanego tokenu"):
        check(loaded, "example.test", FakeResolver())
    with pytest.raises(VerificationError, match="nie jest w magazynie"):
        issue_token(loaded, "nieznana.test")


def test_blad_sieci_resolvera_nie_zmienia_statusu(loaded):
    issue_token(loaded, "example.test")

    class Broken:
        def txt(self, name):
            raise NetworkError("brak sieci")

    with pytest.raises(NetworkError):
        check(loaded, "example.test", Broken())
    assert loaded.find_domain("example.test").verification_status is VerificationStatus.PENDING


def test_doh_resolver_parsuje_odpowiedz_json():
    body = json.dumps(
        {
            "Status": 0,
            "Answer": [
                {"name": "example.test", "type": 16, "data": '"org-intel-verification=" "abc123"'},
                {"name": "example.test", "type": 16, "data": '"v=spf1 -all"'},
                {"name": "example.test", "type": 1, "data": "192.0.2.1"},
            ],
        }
    )
    client = FakeClient(Response(200, body))
    assert DohResolver(client).txt("example.test") == ["org-intel-verification=abc123", "v=spf1 -all"]
    url, headers = client.calls[0]
    assert url.startswith("https://cloudflare-dns.com/dns-query?") and "name=example.test" in url and "type=TXT" in url
    assert headers["Accept"] == "application/dns-json"


def test_doh_resolver_bledy():
    with pytest.raises(NetworkError):
        DohResolver(FakeClient(Response(500, ""))).txt("example.test")
    with pytest.raises(NetworkError):
        DohResolver(FakeClient(Response(200, "nie json"))).txt("example.test")
    assert DohResolver(FakeClient(Response(200, json.dumps({"Status": 3})))).txt("x.test") == []


# --- konektor katalogu HIBP ------------------------------------------------------------------------

BODY = json.dumps([{"Name": "DemoBreach", "Domain": "shop.example.test", "IsVerified": True}])


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t
        self.sleeps: list[float] = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def connector(tmp_path, client, clock=None, ua="test-firma org-intel/0.1 (kontakt@example.test)", **kw):
    clock = clock or Clock()
    return HibpCatalogClient(ua, tmp_path / "cache", client=client, clock=clock.now, sleep=clock.sleep, **kw), clock


def test_konektor_wymaga_user_agent(tmp_path):
    with pytest.raises(ConfigError):
        HibpCatalogClient("  ", tmp_path)


def test_konektor_pobiera_i_cache_trafia_bez_drugiego_zapytania(tmp_path):
    client = FakeClient(Response(200, BODY))
    conn, clock = connector(tmp_path, client)
    first = conn.fetch()
    assert not first.from_cache and first.text == BODY
    assert client.calls[0][0] == CATALOG_URL
    assert client.calls[0][1]["User-Agent"].startswith("test-firma")
    clock.t += 3600
    second = connector(tmp_path, client, clock)[0].fetch()  # nowy obiekt: cache z dysku
    assert second.from_cache and second.text == BODY
    assert len(client.calls) == 1


def test_cache_wygasa_po_24h_i_refresh_omija_cache(tmp_path):
    client = FakeClient(Response(200, BODY))
    conn, clock = connector(tmp_path, client)
    conn.fetch()
    clock.t += 24 * 3600 + 1
    assert not conn.fetch().from_cache
    assert len(client.calls) == 2
    assert not conn.fetch(refresh=True).from_cache
    assert len(client.calls) == 3


def test_limit_zapytan_min_odstep(tmp_path):
    client = FakeClient(Response(200, BODY))
    conn, clock = connector(tmp_path, client)
    conn.fetch(refresh=True)
    conn.fetch(refresh=True)
    assert clock.sleeps and clock.sleeps[0] == pytest.approx(1.6)


def test_429_z_retry_after_ponawia(tmp_path):
    client = FakeClient([Response(429, "", {"Retry-After": "7"}), Response(200, BODY)])
    conn, clock = connector(tmp_path, client)
    out = conn.fetch()
    assert out.text == BODY and len(client.calls) == 2
    assert 7.0 in clock.sleeps


def test_429_w_kolko_konczy_sie_bledem_po_3_probach(tmp_path):
    client = FakeClient(Response(429, "", {"retry-after": "1"}))
    conn, _ = connector(tmp_path, client)
    with pytest.raises(NetworkError) as err:
        conn.fetch()
    assert err.value.status == 429 and len(client.calls) == MAX_ATTEMPTS == 3
    assert not conn.cache_path.exists()


def test_retry_after_ma_gorny_limit(tmp_path):
    client = FakeClient([Response(429, "", {"Retry-After": "99999"}), Response(200, BODY)])
    conn, clock = connector(tmp_path, client)
    conn.fetch()
    assert max(clock.sleeps) <= 120.0


@pytest.mark.parametrize(
    "resp, msg",
    [
        (Response(403, ""), "User-Agent"),
        (Response(500, ""), "500"),
        (Response(200, "nie json"), "JSON"),
        (Response(200, "{}"), "listy"),
    ],
)
def test_bledy_odpowiedzi_nie_trafiaja_do_cache(tmp_path, resp, msg):
    conn, _ = connector(tmp_path, FakeClient(resp))
    with pytest.raises(NetworkError, match=msg):
        conn.fetch()
    assert not conn.cache_path.exists()


def test_konektor_uzywa_tylko_publicznego_katalogu():
    import org_intel.hibp_catalog as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("breachedaccount", "pasteaccount", "stealerlogs", "breacheddomain"):
        assert f"/{forbidden}" not in source
    assert CATALOG_URL == "https://haveibeenpwned.com/api/v3/breaches"


def test_forbidden_client_pomocniczy_dziala():
    c = ForbiddenClient()
    with pytest.raises(AssertionError):
        c.get("https://x.test")

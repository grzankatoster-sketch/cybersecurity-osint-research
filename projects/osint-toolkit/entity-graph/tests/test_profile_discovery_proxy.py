"""Fail-closed kanału wyszukiwania profili (Brave): OSINT_PROXY/Tor nie może być ominięty połączeniem bezpośrednim,
brak / błąd / nieosiągalność proxy zatrzymują skan. Bez sieci: atrapa transportu i zablokowane gniazda."""

from __future__ import annotations

import json
import logging
import socket
import sys
import urllib.request
from pathlib import Path
from typing import ClassVar

import pytest
from test_profile_discovery import FB, IG, KEY, PERSON, FakeBrave, digest, graph, run_search, web

from entity_graph import cli
from entity_graph import profile_discovery as pd

SOCKS = "socks5h://127.0.0.1:9150"


@pytest.fixture
def env(monkeypatch, tmp_path):
    for k in (pd.KEY_ENV, pd.FILE_ENV, pd.PROXY_ENV, pd.REQUIRE_PROXY_ENV, pd.OSINT_PROXY_ENV):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(pd, "DEFAULT_FILE", tmp_path / "brak" / "brave.env")
    monkeypatch.setenv(pd.KEY_ENV, KEY)
    return monkeypatch


@pytest.fixture
def no_sockets(monkeypatch):
    """Każda próba połączenia sieciowego kończy test błędem (dowód, że nic nie wychodzi)."""
    attempts = []

    def blocked(*args, **_kwargs):
        attempts.append(args)
        raise AssertionError("próba połączenia sieciowego")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    return attempts


@pytest.fixture
def case(tmp_path):
    out = tmp_path / "sprawa"
    purpose = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/58"
    assert (
        cli.main(["run", "--purpose", purpose, "--person", PERSON, "--offline", "--no-evidence", "--out", str(out)])
        == 0
    )
    return out


def _person(case):
    g = graph(case)
    return g, next(n for n in g.nodes.values() if n.value == PERSON)


# --- OSINT_PROXY (Tor) wymusza proxy: bez obsługiwanego proxy odmowa, zero zapytań --------------------------------


def test_osint_proxy_socks_without_brave_proxy_blocks_every_query(env, case, no_sockets, capsys):
    env.setenv(pd.OSINT_PROXY_ENV, SOCKS)
    fake = FakeBrave(web(FB))
    before = (digest(case / "graph.json"), digest(case / "audit.jsonl"))
    assert run_search(env, case, fake) == cli.EXIT_CONFIG
    err = capsys.readouterr().err
    assert pd.OSINT_PROXY_ENV in err and "bez połączenia bezpośredniego" in err
    assert fake.calls == [] and not no_sockets
    assert (digest(case / "graph.json"), digest(case / "audit.jsonl")) == before


def test_osint_proxy_credentials_never_appear_in_messages(env, case, no_sockets, capsys):
    env.setenv(pd.OSINT_PROXY_ENV, "socks5h://login:SEKRET-123@127.0.0.1:9050")
    assert run_search(env, case, FakeBrave(web(FB))) == cli.EXIT_CONFIG
    out = capsys.readouterr()
    assert "SEKRET-123" not in out.out + out.err and "login" not in out.err
    assert "SEKRET-123" not in repr(pd.load_config())


def test_osint_proxy_from_config_file_is_enforced_too(env, tmp_path):
    cfg_file = tmp_path / "brave.env"
    cfg_file.write_text(f"{pd.OSINT_PROXY_ENV}={SOCKS}\n", encoding="utf-8")
    env.setenv(pd.FILE_ENV, str(cfg_file))
    cfg = pd.load_config()
    assert cfg.require_proxy and cfg.blocking_problem() and cfg.proxy is None


def test_http_osint_proxy_is_used_as_the_only_channel(env):
    env.setenv(pd.OSINT_PROXY_ENV, "http://127.0.0.1:8118")
    cfg = pd.load_config()
    assert cfg.blocking_problem() is None and cfg.proxy == "http://127.0.0.1:8118" and cfg.require_proxy
    assert cfg.channel() == "tylko przez BRAVE_PROXY http://127.0.0.1:8118"


def test_brave_proxy_wins_over_socks_osint_proxy(env):
    env.setenv(pd.OSINT_PROXY_ENV, SOCKS)
    env.setenv(pd.PROXY_ENV, "http://127.0.0.1:9080")  # np. Tor HTTPTunnelPort
    cfg = pd.load_config()
    assert cfg.blocking_problem() is None and cfg.proxy == "http://127.0.0.1:9080"


def test_require_proxy_without_proxy_blocks(env, case, no_sockets):
    env.setenv(pd.REQUIRE_PROXY_ENV, "1")
    fake = FakeBrave(web(FB))
    assert run_search(env, case, fake) == cli.EXIT_CONFIG and fake.calls == [] and not no_sockets


def test_without_any_proxy_policy_direct_channel_is_still_allowed(env):
    cfg = pd.load_config()  # brak OSINT_PROXY i BRAVE_REQUIRE_PROXY: zachowanie bez zmian
    assert cfg.blocking_problem() is None and cfg.proxy is None and not cfg.require_proxy


# --- proxy nieosiągalne przed startem: zero zapytań ---------------------------------------------------------------


def test_unreachable_proxy_before_start_sends_nothing(env, case):
    env.setenv(pd.PROXY_ENV, "http://127.0.0.1:9080")
    g, person = _person(case)
    fake = FakeBrave(web(FB))
    probed = []

    def probe(host, port):
        probed.append((host, port))
        return False

    with pytest.raises(pd.ConfigError, match="nieosiągalne"):
        pd.search(g, person, "", pd.Limits(), pd.load_config(), http=fake, probe=probe)
    assert probed == [("127.0.0.1", 9080)] and fake.calls == []


def test_real_probe_touches_only_the_proxy_address(monkeypatch):
    seen = []

    def fake_connect(address, timeout=None):
        seen.append((address, timeout))
        raise OSError("odmowa")

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    assert pd._proxy_reachable("127.0.0.1", 9080) is False
    assert seen == [(("127.0.0.1", 9080), pd.PROXY_PROBE_SECONDS)]


# --- błąd połączenia przez proxy w trakcie: zatrzymanie bez ponowień --------------------------------------------


@pytest.mark.parametrize("error", ["ConnectorTimeout", "TransportError"])
def test_proxy_error_during_scan_halts_without_retry(env, case, error):
    env.setenv(pd.PROXY_ENV, "http://127.0.0.1:9080")
    pkg, _ = pd.load_connector()
    fake = FakeBrave(getattr(pkg, error)("przez proxy"), web(IG))
    assert run_search(env, case, fake, "--max-calls", "6") == 1
    rep = pd.state(graph(case))["runs"][-1]
    assert len(fake.calls) == 1 and rep["totals"]["calls"] == 1  # bez ponowienia i bez kolejnych zapytań
    assert rep["queries"][0]["reason_code"] == "proxy_down" and rep["queries"][0]["status"] == "ERROR"
    assert "fail-closed" in rep["stop_reason"] and rep["partial"] is True
    assert {s["why"] for s in rep["skipped"]} == {rep["stop_reason"]}


def test_without_proxy_transport_errors_are_still_retried_once(env, case):
    pkg, _ = pd.load_connector()
    fake = FakeBrave(pkg.ConnectorTimeout("t"))
    assert run_search(env, case, fake, "--max-calls", "3") == 1
    rep = pd.state(graph(case))["runs"][-1]
    assert rep["queries"][0]["reason_code"] == "timeout" and rep["queries"][0]["attempts"] == 2


# --- audyt fail-closed: kanał, brak rotacji i podrabiania, brak sekretów -----------------------------------------

SECRET = "tajne"
PROXY_URL = f"http://login:{SECRET}@127.0.0.1:9080"
UA = "osint-connectors/0.1 (autoryzowany OSINT)"


class _FakeResponse:
    """Odpowiedź atrapy transportu urllib (bez gniazd)."""

    status = 200
    headers: ClassVar[dict] = {}

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _payload():
    return {
        "type": "search",
        "query": {"original": "x", "more_results_available": False},
        "web": {"results": [{"title": FB[1], "url": FB[0], "description": FB[2]}]},
    }


def _is_loop_selfpipe() -> bool:
    """asyncio.run na Windows łączy dwa lokalne gniazda (socketpair): to nie jest ruch sieciowy."""
    frame = sys._getframe(2)
    return frame.f_code.co_name == "_fallback_socketpair"


def _refuse_connect(monkeypatch):
    """Nic nie wychodzi: connect rejestruje adres i odmawia (jak martwe proxy). Wyjątek: wewnętrzne gniazda pętli."""
    addresses = []
    real_connect = socket.socket.connect

    def refuse(self, address, *args, **kwargs):
        if _is_loop_selfpipe():
            return real_connect(self, address, *args, **kwargs)
        addresses.append(address)
        raise ConnectionRefusedError("odmowa (atrapa)")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", lambda address, *a, **k: refuse(None, address))
    return addresses


@pytest.fixture
def no_client(monkeypatch):
    """Dowód, że transport w ogóle nie powstał (zero zapytań, zero połączeń)."""
    pkg, _ = pd.load_connector()
    built = []

    def forbidden(*args, **kwargs):
        built.append(kwargs)
        raise AssertionError("utworzono klienta HTTP mimo zablokowanej konfiguracji")

    monkeypatch.setattr(pkg, "UrllibClient", forbidden)
    return built


@pytest.mark.parametrize("value", ["1", "true", "tak", "yes", "on", "2", "enabled", "TAK", "włącz"])
def test_require_proxy_any_value_but_explicit_off_requires_proxy(env, value):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.REQUIRE_PROXY_ENV, value)
    cfg = pd.load_config()
    assert cfg.require_proxy and cfg.blocking_problem() and cfg.proxy is None


@pytest.mark.parametrize("value", ["0", "false", "no", "nie", "off", "NIE", "False"])
def test_require_proxy_explicit_off_values_do_not_require(env, value):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.REQUIRE_PROXY_ENV, value)
    cfg = pd.load_config()
    assert not cfg.require_proxy and cfg.blocking_problem() is None


@pytest.mark.parametrize(
    "value",
    [
        f"login:{SECRET}@127.0.0.1:9050",
        f"{SECRET}:x@127.0.0.1:9050",
        f"socks5h://login:{SECRET}@127.0.0.1:9050",
        SECRET,
    ],
)
def test_osint_proxy_message_never_echoes_value_fragments(env, value):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.OSINT_PROXY_ENV, value)
    cfg = pd.load_config()
    text = (cfg.blocking_problem() or "") + repr(cfg) + cfg.channel()
    assert cfg.blocking_problem() and SECRET not in text and "login" not in text


def test_missing_required_proxy_sends_nothing_and_message_is_deterministic(env, case, no_client, no_sockets):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.REQUIRE_PROXY_ENV, "1")
    g, person = _person(case)
    fake = FakeBrave(web(FB))
    messages = []
    for _ in range(2):
        with pytest.raises(pd.ConfigError) as exc:
            pd.search(g, person, "", pd.Limits(), pd.load_config(), http=fake, probe=lambda h, p: True)
        messages.append(str(exc.value))
    assert messages[0] == messages[1]
    assert "wymaga proxy" in messages[0] and "bez połączenia bezpośredniego" in messages[0]
    assert fake.calls == [] and no_client == [] and not no_sockets and pd.META_KEY not in g.meta


@pytest.mark.parametrize(
    "value",
    [
        "http://login:tajne@127.0.0.1",
        "socks5h://127.0.0.1:9150",
        "http://127.0.0.1:99999",
        "https://127.0.0.1:8443",
        "127.0.0.1:8080",
        "http://a b:1",
    ],
)
def test_invalid_proxy_sends_nothing_even_with_probe_and_transport(env, case, no_client, no_sockets, value):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.PROXY_ENV, value)
    g, person = _person(case)
    fake = FakeBrave(web(FB))
    with pytest.raises(pd.ConfigError) as exc:
        pd.search(g, person, "", pd.Limits(), pd.load_config(), http=fake, probe=lambda h, p: True)
    assert "BRAVE_PROXY" in str(exc.value) and SECRET not in str(exc.value)
    assert fake.calls == [] and no_client == [] and not no_sockets


def test_config_built_outside_load_config_with_bad_proxy_is_config_error_not_crash(case, no_client, no_sockets):
    g, person = _person(case)
    cfg = pd.BraveConfig(key=KEY, proxy="socks5h://127.0.0.1:9150", require_proxy=True)
    fake = FakeBrave(web(FB))
    with pytest.raises(pd.ConfigError, match="http://host:port"):
        pd.search(g, person, "", pd.Limits(), cfg, http=fake, probe=lambda h, p: True)
    assert fake.calls == [] and no_client == [] and not no_sockets


def test_proxy_rejected_by_transport_is_config_error_without_secret(env, case, no_sockets):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(
        pd.PROXY_ENV, f"http://login:pa#{SECRET}@127.0.0.1:9080"
    )  # regex konfiguracji przepuszcza, transport nie
    g, person = _person(case)
    with pytest.raises(pd.ConfigError) as exc:
        pd.search(g, person, "", pd.Limits(), pd.load_config(), probe=lambda h, p: True)
    assert "zapytania zablokowane" in str(exc.value) and SECRET not in str(exc.value) and not no_sockets


def test_unreachable_proxy_with_real_probe_disables_brave_deterministically(env, case, no_client, monkeypatch, caplog):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.PROXY_ENV, PROXY_URL)
    addresses = []

    def refuse(address, timeout=None):
        addresses.append(address)
        raise OSError("odmowa (atrapa)")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("połączenie poza sondą proxy"))
    g, person = _person(case)
    messages = []
    caplog.set_level(logging.DEBUG)
    for _ in range(2):
        with pytest.raises(pd.ConfigError) as exc:
            pd.search(g, person, "", pd.Limits(), pd.load_config())
        messages.append(str(exc.value))
    expected = (
        "proxy 127.0.0.1:9080 jest nieosiągalne: zapytania zablokowane (fail-closed, bez połączenia bezpośredniego)"
    )
    assert messages[0] == messages[1] == expected
    assert addresses == [("127.0.0.1", 9080)] * 2 and no_client == []  # tylko sonda samego proxy, żadnego klienta
    assert SECRET not in "".join(messages) + caplog.text and pd.META_KEY not in g.meta


def test_working_proxy_starts_scan_through_that_proxy_only(env, case):
    env.setenv(pd.KEY_ENV, KEY)
    no_sockets = _refuse_connect(env)  # atrapa transportu nie łączy się z niczym; gniazda zablokowane
    env.setenv(pd.PROXY_ENV, PROXY_URL)
    g, person = _person(case)
    fake = FakeBrave(web(FB), web(IG), web())
    probed = []
    rep = pd.search(
        g,
        person,
        "",
        pd.Limits(),
        pd.load_config(),
        http=fake,
        probe=lambda host, port: probed.append((host, port)) or True,
    )
    assert probed == [("127.0.0.1", 9080)] and fake.calls and rep["totals"]["calls"] == len(fake.calls)
    assert rep["channel"] == "tylko przez BRAVE_PROXY http://127.0.0.1:9080" and not no_sockets
    assert all(q["reason_code"] in ("results", "empty") for q in rep["queries"])


def test_one_fixed_proxy_for_the_whole_round_no_rotation(env, case, monkeypatch):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.PROXY_ENV, PROXY_URL)
    pkg, _ = pd.load_connector()
    clients = []

    class Recorder(FakeBrave):
        def __init__(self, **kwargs):
            super().__init__(web(FB), web(IG), web())
            clients.append(kwargs)

    monkeypatch.setattr(pkg, "UrllibClient", Recorder)
    g, person = _person(case)
    rep = pd.search(g, person, "", pd.Limits(calls=6), pd.load_config(), probe=lambda h, p: True)
    assert rep["totals"]["calls"] >= 2
    assert clients == [{"proxy": PROXY_URL}]  # jeden klient, jedno proxy, bez listy zapasowych i bez zmian w trakcie


def test_user_agent_is_fixed_honest_and_same_in_every_request(env, case, monkeypatch):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.PROXY_ENV, PROXY_URL)
    sent = []

    def fake_open(self, req, data=None, timeout=None):
        keys = [k.lower() for k in req.headers] + [k.lower() for k in req.unredirected_hdrs]
        sent.append({"ua": req.get_header("User-agent"), "keys": keys})
        return _FakeResponse(_payload())

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fake_open)
    g, person = _person(case)
    rep = pd.search(g, person, "", pd.Limits(calls=6), pd.load_config(), probe=lambda h, p: True)
    assert len(sent) == rep["totals"]["calls"] >= 2
    assert {s["ua"] for s in sent} == {UA} and "Mozilla" not in UA
    forbidden = {"referer", "cookie", "x-forwarded-for", "via", "accept-language", "sec-ch-ua"}
    assert all(not forbidden & set(s["keys"]) for s in sent)


def test_midscan_proxy_failure_never_falls_back_to_direct_even_with_system_proxy_env(env, case, caplog):
    """Prawdziwy transport: martwe proxy w trakcie => stop rundy, jedyny adres połączenia to BRAVE_PROXY (nie
    HTTPS_PROXY, nie host dostawcy), a sekret z adresu proxy nie wychodzi do wyjątków, raportu i logów."""
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.PROXY_ENV, PROXY_URL)
    for name in ("HTTPS_PROXY", "https_proxy"):
        env.setenv(name, "http://10.9.9.9:1")
    for name in ("NO_PROXY", "no_proxy"):
        env.setenv(name, "*")
    addresses = _refuse_connect(env)
    caplog.set_level(logging.DEBUG)
    g, person = _person(case)
    rep = pd.search(g, person, "", pd.Limits(calls=6), pd.load_config(), probe=lambda h, p: True)
    assert addresses and set(addresses) == {("127.0.0.1", 9080)}
    assert rep["totals"]["calls"] == 1 == len(rep["queries"])  # bez ponowień i bez kolejnych zapytań
    assert rep["queries"][0]["reason_code"] == "proxy_down" and rep["partial"] is True
    assert "fail-closed" in rep["stop_reason"] and rep["skipped"]
    blob = (
        json.dumps(rep, ensure_ascii=False)
        + json.dumps(g.meta, ensure_ascii=False, default=str)
        + "".join(r.error + r.note for r in g.runs)
        + repr(pd.load_config())
        + caplog.text
    )
    assert SECRET not in blob and "login" not in blob


def test_secret_in_proxy_never_reaches_cli_output_audit_graph_or_report(env, case, monkeypatch, capsys, caplog):
    env.setenv(pd.KEY_ENV, KEY)
    env.setenv(pd.PROXY_ENV, PROXY_URL)
    monkeypatch.setattr(cli, "PROFILE_HTTP", None)
    monkeypatch.setattr(pd, "_proxy_reachable", lambda host, port, timeout=0: False)
    caplog.set_level(logging.DEBUG)
    before = digest(case / "graph.json")
    assert cli.main(["szukaj-profili", str(case), "--person", PERSON]) == cli.EXIT_CONFIG
    out = capsys.readouterr()
    assert "nieosiągalne" in out.err and "127.0.0.1:9080" in out.err
    files = [p for p in case.iterdir() if p.is_file() and p.suffix in (".json", ".jsonl", ".html", ".md", ".txt")]
    texts = [out.out, out.err, caplog.text] + [p.read_text(encoding="utf-8", errors="replace") for p in files]
    assert files and all(SECRET not in t and "login:" not in t for t in texts)
    assert digest(case / "graph.json") == before


def test_no_default_or_automatic_tor_channel(env):
    """Brak jakiejkolwiek konfiguracji kanału: żadne proxy (także Tor 9050/9150) nie jest domyślne ani zapasowe."""
    env.setenv(pd.KEY_ENV, KEY)
    cfg = pd.load_config()
    assert cfg.proxy is None and not cfg.require_proxy
    source = Path(pd.__file__).read_text(encoding="utf-8")
    assert "9050" not in source and "9150" not in source

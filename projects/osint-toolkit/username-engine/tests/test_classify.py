from username_engine.classify import classify
from username_engine.models import Response, Site, Status

URL = "https://ex.com/u/{username}"


def site(**kw) -> Site:
    return Site(name="Ex", url=URL, **kw)


def resp(status=200, text="", final_url=None, username="alice", error=None):
    if final_url is None and status is not None:
        final_url = URL.replace("{username}", username)
    return Response(status=status, text=text, final_url=final_url or "", error=error)


def test_network_error_is_error_not_absence():
    st, _, reason = classify(site(), Response(status=None, error="timeout"), "alice")
    assert st is Status.ERROR and reason == "timeout"


def test_rate_limit_and_5xx_are_errors():
    assert classify(site(), resp(429), "alice")[0] is Status.ERROR
    assert classify(site(), resp(503), "alice")[0] is Status.ERROR


def test_server_error_as_explicit_absence_code():
    """Hejto: brak konta = 500. Gdy reguła ma m_code=500, to NOT_FOUND; bez tego 500 to zawsze ERROR."""
    assert classify(site(e_code=200, m_code=500), resp(500, "err"), "alice")[0] is Status.NOT_FOUND
    assert classify(site(e_code=200), resp(500, "err"), "alice")[0] is Status.ERROR


def test_cloudflare_challenge_is_error():
    page = "<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/x'></script>"
    assert classify(site(e_strings=["profile"]), resp(403, page), "alice")[0] is Status.ERROR


def test_cloudflare_script_on_normal_page_is_not_block():
    """Skrypt challenge-platform bywa wstrzykiwany do zwykłych stron 200/404 — to nie blokada."""
    page = "<script src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'></script> User not found"
    st, _, _ = classify(site(e_strings=["profile"], m_strings=["User not found"]), resp(404, page), "alice")
    assert st is Status.NOT_FOUND


def test_page_differing_from_control_only_is_weak():
    r = resp(200, "a" * 1000)
    c = resp(200, "b" * 600, username="zq81kdm2")
    st, conf, _ = classify(site(check_type="status_code"), r, "alice", c, "zq81kdm2")
    assert st is Status.FOUND and conf < 0.6


def test_presence_string_found():
    st, conf, _ = classify(site(e_strings=["class=\"profile\""], m_strings=["Not found"]),
                           resp(200, '<div class="profile">'), "alice")
    assert st is Status.FOUND and conf >= 0.9


def test_absence_string_wins():
    st, _, _ = classify(site(e_strings=["profile"], m_strings=["User not found"]),
                        resp(200, "profile ... User not found"), "alice")
    assert st is Status.NOT_FOUND


def test_empty_absence_string_does_not_block_hit():
    """Błąd Blackbirda: pusty m_string ('' in tekst == True) blokował trafienie na zawsze."""
    st, _, _ = classify(site(e_strings=["avatar"], m_strings=[""], e_code=200, m_code=302),
                        resp(200, "<img class=avatar>"), "alice")
    assert st is Status.FOUND


def test_missing_presence_string_is_not_found():
    st, _, reason = classify(site(e_strings=["avatar"]), resp(200, "<html>home</html>"), "alice")
    assert st is Status.NOT_FOUND and "obecności" in reason


def test_expected_code_mismatch_is_not_found():
    assert classify(site(e_code=200, m_code=404), resp(404), "alice")[0] is Status.NOT_FOUND


def test_redirect_away_from_profile_is_not_found():
    st, _, reason = classify(site(), resp(200, "welcome", final_url="https://ex.com/"), "alice")
    assert st is Status.NOT_FOUND and "przekierowanie" in reason


def test_redirect_to_site_search_with_name_is_not_found():
    """Giphy (pomiar 03.10.2026): /{nazwa} -> /explore/{nazwa}; wyniki wyszukiwania mają tekst obecności konta
    ("@type":"Person" twórców GIF-ów), więc nazwa z popularnym słowem dawała FOUND 0.99."""
    s = site(e_strings=['"@type":"Person"'])
    for final in ("https://ex.com/explore/alice-sketch", "https://ex.com/search?q=alice-sketch",
                  "https://ex.com/tag/alice-sketch"):
        st, _, reason = classify(s, resp(200, '{"@type":"Person"}', final_url=final, username="alice-sketch"),
                                 "alice-sketch")
        assert st is Status.NOT_FOUND and "wyszukiwar" in reason, final


def test_search_url_requested_on_purpose_is_not_a_redirect():
    s = Site(name="S", url="https://ex.com/search?q={username}", e_strings=["profil"])
    r = Response(status=200, text='<a href="/u/alice">profil</a> "alice"', final_url="https://ex.com/search?q=alice")
    assert classify(s, r, "alice")[0] is Status.FOUND


def test_login_redirect_with_name_in_next_param_is_error():
    """'/login?next=/u/alice' zawiera nazwę, ale to strona logowania — nie FOUND, nie NOT_FOUND."""
    r = resp(200, "x" * 900, final_url="https://ex.com/accounts/login/?next=/u/alice")
    st, _, reason = classify(site(check_type="status_code"), r, "alice")
    assert st is Status.ERROR and "logowania" in reason


def test_password_form_instead_of_profile_is_error():
    page = "<form><input name=u><input type='password' name=p></form>"
    assert classify(site(), resp(200, page), "alice")[0] is Status.ERROR
    assert classify(site(e_strings=["avatar"]), resp(200, page), "alice")[0] is Status.ERROR


def test_header_login_form_does_not_hide_profile_confirmed_by_control():
    page = "<form><input type=password></form><h1>Profil alice</h1>" + "x" * 900
    r, c = resp(200, page), resp(404, "nie ma", username="zq81kdm2")
    st, conf, _ = classify(site(check_type="status_code"), r, "alice", c, "zq81kdm2")
    assert st is Status.FOUND and conf >= 0.8


def test_unrecognized_page_is_error_not_absence():
    """Reguła zna tekst obecności i braku konta, strona nie pasuje do żadnego -> ERROR, nie NOT_FOUND."""
    s = site(e_strings=["avatar"], m_strings=["User not found"])
    st, _, reason = classify(s, resp(200, "<html>Please wait</html>"), "alice")
    assert st is Status.ERROR and "nierozpoznana" in reason


def test_password_form_does_not_hide_real_profile():
    page = "<div class=avatar></div><input type=password>"   # profil + formularz logowania w nagłówku
    assert classify(site(e_strings=["avatar"]), resp(200, page), "alice")[0] is Status.FOUND


def test_202_waf_challenge_is_error_unless_rule_expects_it():
    assert classify(site(), resp(202, ""), "alice")[0] is Status.ERROR
    assert classify(site(e_code=202, e_strings=["ok"]), resp(202, "ok"), "alice")[0] is Status.FOUND


def test_status_only_without_control_is_low_confidence():
    st, conf, _ = classify(site(check_type="status_code"), resp(200, "x" * 500), "alice")
    assert st is Status.FOUND and conf < 0.5


def test_soft_404_detected_by_control():
    page = "<html>Sorry, nothing here for {n}</html>" + "x" * 1000
    r = resp(200, page.format(n="alice"))
    c = resp(200, page.format(n="zq81kdm2"), username="zq81kdm2")
    st, _, reason = classify(site(check_type="status_code"), r, "alice", c, "zq81kdm2")
    assert st is Status.NOT_FOUND and "soft-404" in reason


def test_control_with_different_code_confirms():
    r = resp(200, "profile of alice" + "y" * 800)
    c = resp(404, "nope", username="zq81kdm2")
    st, conf, _ = classify(site(check_type="status_code"), r, "alice", c, "zq81kdm2")
    assert st is Status.FOUND and conf >= 0.8


def test_rule_matching_random_name_is_unreliable():
    """Np. Sherlock/YouTube: reguła pasuje do każdej nazwy -> nie FOUND."""
    s = site(e_strings=["ytInitialData"])
    r = resp(200, "ytInitialData alice")
    c = resp(200, "ytInitialData zq81kdm2", username="zq81kdm2")
    st, _, reason = classify(s, r, "alice", c, "zq81kdm2")
    assert st is Status.ERROR and "niewiarygodna" in reason


def test_control_failure_does_not_flip_result():
    s = site(e_strings=["avatar"])
    st, conf, _ = classify(s, resp(200, "avatar"), "alice", Response(status=None, error="timeout"), "zq81kdm2")
    assert st is Status.FOUND and conf >= 0.9

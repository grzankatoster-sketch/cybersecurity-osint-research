"""Odmowa dostępu (401/403/407/451) bez dopasowania reguły to ERROR, nie NOT_FOUND."""
import pytest

from username_engine.classify import classify
from username_engine.models import Response, Site, Status

URL = "https://ex.com/u/{username}"
DENIED = (401, 403, 407, 451)


def site(**kw) -> Site:
    return Site(name="Ex", url=URL, **kw)


def resp(status, text="", username="alice"):
    return Response(status=status, text=text, final_url=URL.replace("{username}", username))


@pytest.mark.parametrize("code", DENIED)
def test_access_denied_with_message_rule_is_error(code):
    s = site(e_strings=["profile-header"], m_strings=["User not found"])
    st, conf, _ = classify(s, resp(code, "<html><h1>Forbidden</h1></html>"), "alice")
    assert st is Status.ERROR
    assert conf == 0.0


@pytest.mark.parametrize("code", DENIED)
def test_access_denied_with_status_code_rule_is_error(code):
    s = site(check_type="status_code")
    control = resp(code, "<html>Access denied</html>", username="zq8xk3v1w")
    st, _, _ = classify(s, resp(code, "<html>Access denied</html>"), "alice",
                        control=control, control_name="zq8xk3v1w")
    assert st is Status.ERROR


@pytest.mark.parametrize("code", DENIED)
def test_access_denied_with_status_code_rule_without_control_is_error(code):
    s = site(check_type="status_code")
    st, _, _ = classify(s, resp(code, ""), "alice")
    assert st is Status.ERROR


@pytest.mark.parametrize("code", DENIED)
def test_explicit_m_code_still_means_absence(code):
    s = site(check_type="status_code", m_code=code)
    st, _, _ = classify(s, resp(code, "Forbidden"), "alice")
    assert st is Status.NOT_FOUND


@pytest.mark.parametrize("code", DENIED)
def test_absence_text_still_means_absence(code):
    s = site(e_strings=["profile-header"], m_strings=["User not found"])
    st, _, _ = classify(s, resp(code, "<p>User not found</p>"), "alice")
    assert st is Status.NOT_FOUND

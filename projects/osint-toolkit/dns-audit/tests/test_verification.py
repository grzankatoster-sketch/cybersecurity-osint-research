from dns_audit.verification import detect_verification, detect_verifications, is_email_auth


def test_known_services():
    cases = {
        "google-site-verification=abc123": "Google",
        "MS=ms12345678": "Microsoft 365",
        "facebook-domain-verification=xyz": "Meta",
        "atlassian-domain-verification=Zm9v": "Atlassian",
        "apple-domain-verification=Ab12": "Apple",
        "docusign=1111-2222": "DocuSign",
        "stripe-verification=abc": "Stripe",
        "ZOOM_verify_AbCd": "Zoom",
        "anthropic-domain-verification-xyz=abc": "Anthropic",
        "openai-domain-verification=dv-abc": "OpenAI",
        "have-i-been-pwned-verification=abcdef": "Have I Been Pwned",
    }
    for txt, name in cases.items():
        v = detect_verification(txt)
        assert v is not None, txt
        assert name in v.service, (txt, v.service)


def test_case_insensitive_prefix_and_unknown():
    assert detect_verification("GOOGLE-SITE-VERIFICATION=abc")
    assert detect_verification("hello world") is None
    assert detect_verification("v=spf1 -all") is None


def test_detect_list():
    out = detect_verifications(["v=spf1 -all", "google-site-verification=a", "foo", "MS=ms1"])
    assert [v.service.split()[0] for v in out] == ["Google", "Microsoft"]


def test_is_email_auth():
    assert is_email_auth("v=spf1 -all") and is_email_auth("v=DMARC1; p=none")
    assert not is_email_auth("google-site-verification=a")

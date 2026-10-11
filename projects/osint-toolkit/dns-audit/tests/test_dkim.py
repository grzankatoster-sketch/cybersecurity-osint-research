import base64

from dns_audit.dkim import is_dkim, parse_dkim, rsa_key_bits


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def make_spki(bits: int) -> bytes:
    n = (1 << (bits - 1)) | 1  # dokladnie `bits` bitow
    nb = b"\x00" + n.to_bytes((bits + 7) // 8, "big")
    rsa_pub = _der(0x30, _der(0x02, nb) + _der(0x02, b"\x01\x00\x01"))
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    return _der(0x30, alg + _der(0x03, b"\x00" + rsa_pub))


def txt_for(bits: int, extra: str = "") -> str:
    return "v=DKIM1; k=rsa; " + extra + "p=" + base64.b64encode(make_spki(bits)).decode()


def test_rsa_bits():
    for bits in (1024, 2048, 4096):
        assert rsa_key_bits(make_spki(bits)) == bits


def test_rsa_bits_garbage():
    assert rsa_key_bits(b"") is None
    assert rsa_key_bits(b"\x30\x03\x01\x01\x01") is None
    assert rsa_key_bits(b"\x30\xff") is None


def test_parse_dkim():
    k = parse_dkim(txt_for(2048))
    assert k.key_bits == 2048 and k.key_type == "rsa" and not k.revoked and not k.testing
    assert parse_dkim(txt_for(1024, "t=y; ")).testing


def test_revoked_and_bad_base64():
    assert parse_dkim("v=DKIM1; k=rsa; p=").revoked
    assert parse_dkim("v=DKIM1; p=%%%").errors


def test_ed25519():
    p = base64.b64encode(b"\x01" * 32).decode()
    assert parse_dkim(f"v=DKIM1; k=ed25519; p={p}").key_bits == 256


def test_is_dkim():
    assert is_dkim("v=DKIM1; k=rsa; p=ABC")
    assert is_dkim("k=rsa; p=ABC")  # v opcjonalne
    assert not is_dkim("v=spf1 -all")
    assert not is_dkim("v=DKIM2; p=ABC")


# --- poprawki z przegladu kodu ---------------------------------------------------

def test_ed25519_wrong_length_is_error():
    k = parse_dkim("v=DKIM1; k=ed25519; p=YQ==")
    assert k.errors and k.key_bits is None


def test_unknown_key_type_is_error():
    k = parse_dkim("v=DKIM1; k=foo; p=" + base64.b64encode(b"\x01" * 32).decode())
    assert k.errors and "foo" in " ".join(k.errors)


def test_duplicate_tags_are_error():
    k = parse_dkim(txt_for(2048, "k=ed25519; "))
    assert any("powtorzony tag k" in e for e in k.errors)


def test_rsa_without_exponent_rejected():
    n = b"\x00" + b"\xff" * 128
    only_n = _der(0x30, _der(0x02, n))
    assert rsa_key_bits(only_n) is None  # PKCS#1 bez wykladnika
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    spki = _der(0x30, alg + _der(0x03, b"\x00" + only_n))
    assert rsa_key_bits(spki) is None
    assert parse_dkim("v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode()).errors


def test_valid_keys_have_no_errors():
    assert not parse_dkim(txt_for(2048)).errors
    p = base64.b64encode(b"\x01" * 32).decode()
    assert not parse_dkim(f"v=DKIM1; k=ed25519; p={p}").errors

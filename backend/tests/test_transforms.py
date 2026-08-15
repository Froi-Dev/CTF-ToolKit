import base64

from app.analyzers.crypto.transforms import (
    apply_xor,
    decode_base32,
    decode_base64,
    decode_base85,
    decode_binary,
    decode_hex,
    decode_url,
    rotate_ascii,
)


def test_standard_decoders() -> None:
    expected = b"CTF{decode_me}"
    assert decode_base64(base64.b64encode(expected)) == expected
    assert decode_base32(base64.b32encode(expected)) == expected
    assert decode_hex(expected.hex().encode()) == expected
    assert decode_binary(b" ".join(f"{byte:08b}".encode() for byte in expected)) == expected
    assert decode_url(b"CTF%7Bdecode_me%7D") == expected


def test_base85_variants() -> None:
    expected = b"base85 works"
    ascii85 = decode_base85(base64.a85encode(expected))
    rfc1924 = decode_base85(base64.b85encode(expected))
    assert any(item.data == expected and item.parameter == "Ascii85" for item in ascii85)
    assert any(item.data == expected and item.parameter == "RFC 1924" for item in rfc1924)


def test_rot_caesar_and_xor() -> None:
    assert rotate_ascii(b"KHOOR", 3) == b"HELLO"
    encrypted = apply_xor(b"CTF{xor}", b"key")
    assert apply_xor(encrypted, b"key") == b"CTF{xor}"


def test_malformed_encoded_values_are_rejected() -> None:
    assert decode_base64(b"not valid **") is None
    assert decode_base32(b"123!") is None
    assert decode_hex(b"abc") is None
    assert decode_binary(b"01012") is None
    assert decode_url(b"plain text") is None


"""Ed25519 (RFC 8032) en Python puro: vectores oficiales y firmas generadas con OpenSSL."""

import pytest

from natxajo_auditor.core import ed25519

RFC_SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

OPENSSL_PUBLIC = bytes.fromhex("824f3b6dc94a27216057d7a097741b03684f1031a0cb1988358ebd5b7fc997c3")
OPENSSL_MESSAGE = bytes.fromhex("4e415458414a4f20706c7567696e207061796c6f6164200001")
OPENSSL_SIGNATURE = bytes.fromhex(
    "a6c930c599d5da6eb6dbc62d77d701123b2756ec91d39f98b1fa7a623f3580e87ad754c3bdd1ee0e58515d6763ac502d4c8f23fdbda8ad422aa9777ed4542808"
)


def test_rfc8032_public_key_matches_vector() -> None:
    assert ed25519.public_key(RFC_SECRET) == RFC_PUBLIC


def test_rfc8032_signature_matches_vector() -> None:
    assert ed25519.sign(RFC_SECRET, b"") == RFC_SIGNATURE


def test_rfc8032_signature_verifies() -> None:
    assert ed25519.verify(RFC_PUBLIC, b"", RFC_SIGNATURE)


def test_openssl_signature_verifies() -> None:
    assert ed25519.verify(OPENSSL_PUBLIC, OPENSSL_MESSAGE, OPENSSL_SIGNATURE)


def test_signing_is_deterministic_and_verifiable() -> None:
    message = b"paquete de prueba"
    first = ed25519.sign(RFC_SECRET, message)
    assert first == ed25519.sign(RFC_SECRET, message)
    assert ed25519.verify(RFC_PUBLIC, message, first)


def test_changed_message_is_rejected() -> None:
    assert not ed25519.verify(RFC_PUBLIC, b"otro mensaje", RFC_SIGNATURE)


def test_signature_from_another_key_is_rejected() -> None:
    assert not ed25519.verify(OPENSSL_PUBLIC, b"", RFC_SIGNATURE)


@pytest.mark.parametrize("position", [0, 40, 63])
def test_flipped_bit_in_signature_is_rejected(position: int) -> None:
    tampered = bytearray(RFC_SIGNATURE)
    tampered[position] ^= 0x01
    assert not ed25519.verify(RFC_PUBLIC, b"", bytes(tampered))


def test_malformed_inputs_return_false_without_raising() -> None:
    non_canonical_s = RFC_SIGNATURE[:32] + ed25519.L.to_bytes(32, "little")
    assert not ed25519.verify(RFC_PUBLIC[:31], b"", RFC_SIGNATURE)
    assert not ed25519.verify(RFC_PUBLIC, b"", RFC_SIGNATURE[:63])
    assert not ed25519.verify(RFC_PUBLIC, b"", non_canonical_s)
    assert not ed25519.verify(b"\xff" * 32, b"", RFC_SIGNATURE)


def test_secret_must_have_32_bytes() -> None:
    with pytest.raises(ValueError):
        ed25519.sign(b"corta", b"mensaje")
    with pytest.raises(ValueError):
        ed25519.public_key(b"")

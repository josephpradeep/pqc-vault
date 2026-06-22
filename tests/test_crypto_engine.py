"""
tests/test_crypto_engine.py

Unit tests for the hybrid cryptographic engine.
These tests mock liboqs so they run without the native library installed.
Run: pytest tests/ -v
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

# ─── Mock liboqs before importing crypto_engine ───────────────────────────────

class MockKEM:
    """Fake ML-KEM that uses raw bytes so tests run without liboqs."""

    def __init__(self, algorithm, secret_key=None):
        self.algorithm = algorithm
        self._secret_key = secret_key or b"\x00" * 32

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def generate_keypair(self):
        return b"\x01" * 1184  # ML-KEM-768 public key size

    def export_secret_key(self):
        return b"\x02" * 2400  # ML-KEM-768 secret key size

    def encap_secret(self, public_key):
        # Return (kem_ciphertext, shared_secret)
        kem_ct = b"\x03" * 1088
        shared_secret = b"\x04" * 32
        return kem_ct, shared_secret

    def decap_secret(self, kem_ciphertext):
        return b"\x04" * 32  # Same shared secret


class MockSig:
    """Fake ML-DSA."""

    def __init__(self, algorithm, secret_key=None):
        self.algorithm = algorithm

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def generate_keypair(self):
        return b"\x05" * 1952  # ML-DSA-65 public key size

    def export_secret_key(self):
        return b"\x06" * 4032

    def sign(self, message):
        return b"\x07" * 64

    def verify(self, message, signature, public_key):
        return signature == b"\x07" * 64


@pytest.fixture(autouse=True)
def mock_oqs(monkeypatch):
    import sys

    oqs_mock = MagicMock()
    oqs_mock.KeyEncapsulation = MockKEM
    oqs_mock.Signature = MockSig
    monkeypatch.setitem(sys.modules, "oqs", oqs_mock)
    yield


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_generate_kem_keypair():
    from app.core.crypto_engine import generate_kem_keypair

    pair = generate_kem_keypair("ML-KEM-768")
    assert pair.algorithm == "ML-KEM-768"
    assert len(pair.public_key) == 1184
    assert len(pair.secret_key) == 2400
    # Verify base64 round-trip
    assert base64.b64decode(pair.public_b64()) == pair.public_key


def test_generate_dsa_keypair():
    from app.core.crypto_engine import generate_dsa_keypair

    pair = generate_dsa_keypair("ML-DSA-65")
    assert pair.algorithm == "ML-DSA-65"
    assert len(pair.public_key) == 1952


def test_encrypt_decrypt_roundtrip():
    from app.core.crypto_engine import encrypt_file, decrypt_file, generate_kem_keypair

    pair = generate_kem_keypair()
    plaintext = b"Hello, quantum-safe world!"

    bundle = encrypt_file(plaintext, pair.public_key)

    assert bundle.version == "pqcvault-v1"
    assert bundle.kem_algorithm == "ML-KEM-768"
    assert bundle.signature is None  # No DSA key provided

    recovered = decrypt_file(bundle, pair.secret_key)
    assert recovered == plaintext


def test_encrypt_decrypt_with_signature():
    from app.core.crypto_engine import (
        encrypt_file,
        decrypt_file,
        generate_kem_keypair,
        generate_dsa_keypair,
    )

    kem_pair = generate_kem_keypair()
    dsa_pair = generate_dsa_keypair()
    plaintext = b"Signed and sealed."

    bundle = encrypt_file(plaintext, kem_pair.public_key, dsa_secret_key=dsa_pair.secret_key)
    assert bundle.signature is not None

    recovered = decrypt_file(bundle, kem_pair.secret_key, dsa_public_key=dsa_pair.public_key)
    assert recovered == plaintext


def test_bundle_serialisation_roundtrip():
    from app.core.crypto_engine import encrypt_file, EncryptedBundle, generate_kem_keypair

    pair = generate_kem_keypair()
    plaintext = b"Serialisation test payload 1234"

    bundle = encrypt_file(plaintext, pair.public_key)
    serialised = bundle.to_bytes()
    recovered_bundle = EncryptedBundle.from_bytes(serialised)

    assert recovered_bundle.kem_ciphertext == bundle.kem_ciphertext
    assert recovered_bundle.aes_nonce == bundle.aes_nonce
    assert recovered_bundle.ciphertext == bundle.ciphertext


def test_wrong_key_raises():
    from app.core.crypto_engine import encrypt_file, decrypt_file, generate_kem_keypair

    pair = generate_kem_keypair()
    plaintext = b"Top secret data"

    bundle = encrypt_file(plaintext, pair.public_key)

    # Modify the ciphertext to simulate wrong key / corruption
    import dataclasses
    tampered = dataclasses.replace(
        bundle,
        ciphertext=bytes([b ^ 0xFF for b in bundle.ciphertext])
    )

    with pytest.raises(ValueError, match="AES-GCM decryption failed"):
        decrypt_file(tampered, pair.secret_key)


def test_tampered_signature_raises():
    from app.core.crypto_engine import (
        encrypt_file,
        decrypt_file,
        generate_kem_keypair,
        generate_dsa_keypair,
        EncryptedBundle,
    )

    kem_pair = generate_kem_keypair()
    dsa_pair = generate_dsa_keypair()
    plaintext = b"Authenticity matters."

    bundle = encrypt_file(plaintext, kem_pair.public_key, dsa_secret_key=dsa_pair.secret_key)

    # Tamper with signature
    tampered = EncryptedBundle(
        version=bundle.version,
        kem_algorithm=bundle.kem_algorithm,
        kem_ciphertext=bundle.kem_ciphertext,
        aes_nonce=bundle.aes_nonce,
        ciphertext=bundle.ciphertext,
        signature=b"\xFF" * 64,  # Wrong signature
        dsa_algorithm=bundle.dsa_algorithm,
    )

    with pytest.raises(ValueError, match="Signature verification failed"):
        decrypt_file(tampered, kem_pair.secret_key, dsa_public_key=dsa_pair.public_key)

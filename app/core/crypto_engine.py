"""
app/core/crypto_engine.py

Hybrid Cryptographic Engine
────────────────────────────
Uses a two-layer approach mandated by NIST PQC migration guidance:

  Layer 1 — Symmetric (fast):
      AES-256-GCM encrypts the actual file data using a
      random 256-bit Data Encryption Key (DEK).

  Layer 2 — Asymmetric PQC (quantum-resistant):
      ML-KEM-768 encapsulates the DEK using the recipient's
      public key, so only the private key holder can recover it.

  Optional Layer 3 — Signature:
      ML-DSA-65 signs the ciphertext bundle, proving it was
      created by a known sender (non-repudiation).

Wire format of the encrypted bundle (.pqcvault file):
  ┌─────────────────────────────────────────────────────┐
  │ JSON header (UTF-8)                                  │
  │   version, algorithm, kem_ciphertext (base64),       │
  │   aes_nonce (base64), sig (base64, optional)         │
  │ NEWLINE separator                                    │
  │ AES-GCM ciphertext + 16-byte tag (raw bytes)         │
  └─────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

try:
    import oqs  # liboqs-python
except ImportError as e:
    raise ImportError(
        "liboqs-python is not installed or liboqs shared library is missing. "
        "Run setup.sh to build and install liboqs, then install liboqs-python."
    ) from e


BUNDLE_VERSION = "pqcvault-v1"
AES_NONCE_SIZE = 12  # 96-bit nonce recommended for GCM


# ─────────────────────────────────────────────────────────────────────────────
# Key pair dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class KEMKeyPair:
    """ML-KEM public/private key pair."""
    algorithm: str
    public_key: bytes
    secret_key: bytes

    def public_b64(self) -> str:
        return base64.b64encode(self.public_key).decode()

    def secret_b64(self) -> str:
        return base64.b64encode(self.secret_key).decode()


@dataclass
class DSAKeyPair:
    """ML-DSA public/private key pair."""
    algorithm: str
    public_key: bytes
    secret_key: bytes

    def public_b64(self) -> str:
        return base64.b64encode(self.public_key).decode()

    def secret_b64(self) -> str:
        return base64.b64encode(self.secret_key).decode()


@dataclass
class EncryptedBundle:
    """Everything needed to store and later decrypt a file."""
    version: str
    kem_algorithm: str
    # The KEM ciphertext that the recipient decapsulates to recover the DEK
    kem_ciphertext: bytes
    # AES-GCM nonce (12 bytes)
    aes_nonce: bytes
    # Raw AES-GCM ciphertext + 16-byte authentication tag
    ciphertext: bytes
    # Optional ML-DSA signature over (kem_ciphertext ‖ aes_nonce ‖ ciphertext)
    signature: bytes | None = None
    dsa_algorithm: str | None = None

    def to_bytes(self) -> bytes:
        """Serialise to wire format: JSON header + newline + raw ciphertext."""
        header = {
            "version": self.version,
            "kem_algorithm": self.kem_algorithm,
            "kem_ciphertext": base64.b64encode(self.kem_ciphertext).decode(),
            "aes_nonce": base64.b64encode(self.aes_nonce).decode(),
        }
        if self.signature:
            header["dsa_algorithm"] = self.dsa_algorithm
            header["signature"] = base64.b64encode(self.signature).decode()

        header_bytes = json.dumps(header).encode("utf-8")
        return header_bytes + b"\n" + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedBundle":
        """Deserialise from wire format."""
        sep = data.index(b"\n")
        header = json.loads(data[:sep])
        ciphertext = data[sep + 1:]

        return cls(
            version=header["version"],
            kem_algorithm=header["kem_algorithm"],
            kem_ciphertext=base64.b64decode(header["kem_ciphertext"]),
            aes_nonce=base64.b64decode(header["aes_nonce"]),
            ciphertext=ciphertext,
            signature=base64.b64decode(header["signature"]) if "signature" in header else None,
            dsa_algorithm=header.get("dsa_algorithm"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Key generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_kem_keypair(algorithm: str = settings.KEM_ALGORITHM) -> KEMKeyPair:
    """
    Generate an ML-KEM key pair using liboqs.

    ML-KEM-768 is the NIST-standardised KEM (FIPS 203) providing
    ~128-bit post-quantum security. The public key is shared openly;
    the secret key must be kept private.
    """
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return KEMKeyPair(algorithm=algorithm, public_key=public_key, secret_key=secret_key)


def generate_dsa_keypair(algorithm: str = settings.DSA_ALGORITHM) -> DSAKeyPair:
    """
    Generate an ML-DSA key pair using liboqs.

    ML-DSA-65 is the NIST-standardised signature scheme (FIPS 204).
    Used to sign encrypted bundles for authenticity verification.
    """
    with oqs.Signature(algorithm) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()

    return DSAKeyPair(algorithm=algorithm, public_key=public_key, secret_key=secret_key)


# ─────────────────────────────────────────────────────────────────────────────
# Encryption
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file(
    plaintext: bytes,
    kem_public_key: bytes,
    kem_algorithm: str = settings.KEM_ALGORITHM,
    dsa_secret_key: bytes | None = None,
    dsa_algorithm: str = settings.DSA_ALGORITHM,
) -> EncryptedBundle:
    """
    Encrypt plaintext using hybrid PQC cryptography.

    Steps:
      1. ML-KEM encapsulates a fresh shared secret (the DEK).
      2. AES-256-GCM encrypts the plaintext with that DEK.
      3. Optionally, ML-DSA signs the bundle for authenticity.

    The KEM shared secret is used directly as the AES key — in a
    production system you'd derive it via HKDF for domain separation.
    """
    # ── Step 1: KEM encapsulation ──────────────────────────────────────────
    # encapsulate() returns (kem_ciphertext, shared_secret)
    # shared_secret == DEK, never transmitted in plaintext
    with oqs.KeyEncapsulation(kem_algorithm) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(kem_public_key)

    # Ensure DEK is exactly AES_KEY_SIZE bytes
    dek = shared_secret[: settings.AES_KEY_SIZE]

    # ── Step 2: AES-256-GCM encryption ────────────────────────────────────
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(dek)
    # AESGCM.encrypt() appends the 16-byte authentication tag automatically
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # ── Step 3: Optional ML-DSA signature ─────────────────────────────────
    signature = None
    if dsa_secret_key is not None:
        message_to_sign = kem_ciphertext + nonce + ciphertext
        with oqs.Signature(dsa_algorithm, dsa_secret_key) as signer:
            signature = signer.sign(message_to_sign)

    return EncryptedBundle(
        version=BUNDLE_VERSION,
        kem_algorithm=kem_algorithm,
        kem_ciphertext=kem_ciphertext,
        aes_nonce=nonce,
        ciphertext=ciphertext,
        signature=signature,
        dsa_algorithm=dsa_algorithm if signature else None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Decryption
# ─────────────────────────────────────────────────────────────────────────────

def decrypt_file(
    bundle: EncryptedBundle,
    kem_secret_key: bytes,
    dsa_public_key: bytes | None = None,
) -> bytes:
    """
    Decrypt an EncryptedBundle using the KEM secret key.

    Steps:
      1. Optionally verify the ML-DSA signature.
      2. ML-KEM decapsulates to recover the shared secret (DEK).
      3. AES-256-GCM decrypts and authenticates the ciphertext.

    Raises ValueError on signature or AES authentication failure.
    """
    # ── Step 1: Signature verification (optional but recommended) ──────────
    if bundle.signature is not None and dsa_public_key is not None:
        message_to_verify = bundle.kem_ciphertext + bundle.aes_nonce + bundle.ciphertext
        with oqs.Signature(bundle.dsa_algorithm) as verifier:
            is_valid = verifier.verify(message_to_verify, bundle.signature, dsa_public_key)
        if not is_valid:
            raise ValueError("Signature verification failed — bundle may be tampered.")

    # ── Step 2: KEM decapsulation ──────────────────────────────────────────
    with oqs.KeyEncapsulation(bundle.kem_algorithm, kem_secret_key) as kem:
        shared_secret = kem.decap_secret(bundle.kem_ciphertext)

    dek = shared_secret[: settings.AES_KEY_SIZE]

    # ── Step 3: AES-256-GCM decryption ────────────────────────────────────
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(bundle.aes_nonce, bundle.ciphertext, associated_data=None)
    except Exception as exc:
        raise ValueError("AES-GCM decryption failed — wrong key or corrupted data.") from exc

    return plaintext


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: file-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file_path(
    source: Path,
    dest: Path,
    kem_public_key: bytes,
    dsa_secret_key: bytes | None = None,
) -> EncryptedBundle:
    """Read a file, encrypt it, write the bundle to dest."""
    plaintext = source.read_bytes()
    bundle = encrypt_file(plaintext, kem_public_key, dsa_secret_key=dsa_secret_key)
    dest.write_bytes(bundle.to_bytes())
    return bundle


def decrypt_file_path(
    source: Path,
    dest: Path,
    kem_secret_key: bytes,
    dsa_public_key: bytes | None = None,
) -> None:
    """Read an encrypted bundle file, decrypt it, write plaintext to dest."""
    bundle = EncryptedBundle.from_bytes(source.read_bytes())
    plaintext = decrypt_file(bundle, kem_secret_key, dsa_public_key=dsa_public_key)
    dest.write_bytes(plaintext)

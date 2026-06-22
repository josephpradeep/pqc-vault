"""
app/schemas/vault.py
Pydantic v2 request/response schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# ─── Keys ────────────────────────────────────────────────────────────────────

class KeyGenerateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Human-readable key name")
    algorithm: str = Field(default="ML-KEM-768", description="KEM algorithm (NIST-standardised)")
    include_dsa: bool = Field(default=False, description="Also generate an ML-DSA signing key pair")


class KeyResponse(BaseModel):
    key_id: str
    name: str
    algorithm: str
    public_key_b64: str
    created_at: datetime

    model_config = {"from_attributes": True}


class KeyGenerateResponse(BaseModel):
    kem: KeyResponse
    # Secret keys returned ONCE — never stored. User must save these.
    kem_secret_key_b64: str
    dsa_public_key_b64: Optional[str] = None
    dsa_secret_key_b64: Optional[str] = None
    warning: str = (
        "Store the secret key(s) securely. They are NOT saved on the server "
        "and cannot be recovered. Loss of the secret key means permanent "
        "loss of access to encrypted files."
    )


# ─── Vault entries ────────────────────────────────────────────────────────────

class VaultEntryResponse(BaseModel):
    entry_id: str
    original_filename: str
    original_size_bytes: int
    key_id: str
    has_signature: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class EncryptResponse(BaseModel):
    entry_id: str
    original_filename: str
    vault_path: str
    kem_algorithm: str
    has_signature: bool
    message: str = "File encrypted and stored successfully."


class DecryptRequest(BaseModel):
    entry_id: str = Field(..., description="Vault entry UUID")
    kem_secret_key_b64: str = Field(..., description="Base64-encoded ML-KEM secret key")
    dsa_public_key_b64: Optional[str] = Field(
        default=None,
        description="Base64-encoded ML-DSA public key for signature verification",
    )

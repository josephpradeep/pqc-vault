"""
app/api/routes/vault.py
File vault endpoints — encrypt, decrypt, list, delete.
"""

from __future__ import annotations

import base64
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto_engine import (
    EncryptedBundle,
    encrypt_file,
    decrypt_file,
)
from app.db.models import VaultEntry, VaultKey
from app.db.session import get_db
from app.schemas.vault import (
    DecryptRequest,
    EncryptResponse,
    VaultEntryResponse,
)

router = APIRouter(prefix="/vault", tags=["Vault"])


@router.post("/encrypt", response_model=EncryptResponse, status_code=201)
async def encrypt_upload(
    file: UploadFile = File(...),
    key_id: str = Form(...),
    dsa_secret_key_b64: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    """
    Encrypt an uploaded file using the specified public key.

    Flow:
      1. Look up the ML-KEM public key from the database.
      2. Run hybrid encryption (ML-KEM encapsulation + AES-256-GCM).
      3. Write the .pqcvault bundle to disk.
      4. Store metadata + kem_ciphertext in the database.
    """
    # Resolve the public key
    db_key = await db.get(VaultKey, key_id)
    if not db_key:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found.")

    kem_public_key = base64.b64decode(db_key.public_key_b64)

    # Decrypt optional DSA signing key
    dsa_secret_key: bytes | None = None
    if dsa_secret_key_b64:
        try:
            dsa_secret_key = base64.b64decode(dsa_secret_key_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 for dsa_secret_key_b64.")

    # Read file content
    plaintext = await file.read()
    original_size = len(plaintext)

    # Encrypt
    bundle = encrypt_file(
        plaintext,
        kem_public_key=kem_public_key,
        kem_algorithm=db_key.algorithm,
        dsa_secret_key=dsa_secret_key,
    )

    # Write bundle to disk
    entry_id = str(uuid.uuid4())
    vault_filename = f"{entry_id}.pqcvault"
    vault_path = settings.VAULT_DIR / vault_filename
    vault_path.write_bytes(bundle.to_bytes())

    # Persist metadata
    db_entry = VaultEntry(
        id=entry_id,
        original_filename=file.filename or "unknown",
        original_size_bytes=original_size,
        vault_path=str(vault_path),
        key_id=key_id,
        kem_ciphertext_b64=base64.b64encode(bundle.kem_ciphertext).decode(),
        has_signature=bundle.signature is not None,
    )
    db.add(db_entry)
    await db.commit()

    return EncryptResponse(
        entry_id=entry_id,
        original_filename=file.filename or "unknown",
        vault_path=str(vault_path),
        kem_algorithm=db_key.algorithm,
        has_signature=bundle.signature is not None,
    )


@router.post("/decrypt")
async def decrypt_entry(
    request: DecryptRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Decrypt a vault entry and return the plaintext file.

    The caller must supply their KEM secret key (never stored server-side).
    Optionally supply a DSA public key to verify the bundle's signature.
    """
    db_entry = await db.get(VaultEntry, request.entry_id)
    if not db_entry:
        raise HTTPException(status_code=404, detail="Vault entry not found.")

    vault_path = Path(db_entry.vault_path)
    if not vault_path.exists():
        raise HTTPException(status_code=500, detail="Vault bundle file missing from disk.")

    # Decode secret key
    try:
        kem_secret_key = base64.b64decode(request.kem_secret_key_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 for kem_secret_key_b64.")

    dsa_public_key: bytes | None = None
    if request.dsa_public_key_b64:
        try:
            dsa_public_key = base64.b64decode(request.dsa_public_key_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 for dsa_public_key_b64.")

    # Load and decrypt bundle
    bundle = EncryptedBundle.from_bytes(vault_path.read_bytes())
    try:
        plaintext = decrypt_file(bundle, kem_secret_key, dsa_public_key=dsa_public_key)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{db_entry.original_filename}"',
            "X-Original-Filename": db_entry.original_filename,
        },
    )


@router.get("/", response_model=list[VaultEntryResponse])
async def list_entries(db: AsyncSession = Depends(get_db)):
    """List all vault entries (metadata only — no keys or file contents)."""
    result = await db.execute(select(VaultEntry).order_by(VaultEntry.created_at.desc()))
    entries = result.scalars().all()
    return [
        VaultEntryResponse(
            entry_id=e.id,
            original_filename=e.original_filename,
            original_size_bytes=e.original_size_bytes,
            key_id=e.key_id,
            has_signature=e.has_signature,
            created_at=e.created_at,
        )
        for e in entries
    ]


@router.delete("/{entry_id}", status_code=204)
async def delete_entry(entry_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a vault entry and its bundle file from disk."""
    db_entry = await db.get(VaultEntry, entry_id)
    if not db_entry:
        raise HTTPException(status_code=404, detail="Vault entry not found.")

    # Remove bundle from disk
    vault_path = Path(db_entry.vault_path)
    if vault_path.exists():
        vault_path.unlink()

    await db.delete(db_entry)
    await db.commit()

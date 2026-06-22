"""
app/api/routes/keys.py
Key management endpoints.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto_engine import generate_kem_keypair, generate_dsa_keypair
from app.db.models import VaultKey
from app.db.session import get_db
from app.schemas.vault import KeyGenerateRequest, KeyGenerateResponse, KeyResponse

router = APIRouter(prefix="/keys", tags=["Key Management"])


@router.post("/generate", response_model=KeyGenerateResponse, status_code=201)
async def generate_key(
    request: KeyGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a new ML-KEM key pair (and optionally ML-DSA signing keys).

    The PUBLIC key is stored in the database.
    The SECRET key is returned ONCE and never stored — save it immediately.
    """
    # Check for duplicate name
    existing = await db.scalar(select(VaultKey).where(VaultKey.name == request.name))
    if existing:
        raise HTTPException(status_code=409, detail=f"Key with name '{request.name}' already exists.")

    # Generate ML-KEM key pair
    kem_pair = generate_kem_keypair(request.algorithm)

    # Persist only the public key
    db_key = VaultKey(
        name=request.name,
        algorithm=kem_pair.algorithm,
        public_key_b64=kem_pair.public_b64(),
    )
    db.add(db_key)
    await db.commit()
    await db.refresh(db_key)

    response = KeyGenerateResponse(
        kem=KeyResponse(
            key_id=db_key.id,
            name=db_key.name,
            algorithm=db_key.algorithm,
            public_key_b64=db_key.public_key_b64,
            created_at=db_key.created_at,
        ),
        kem_secret_key_b64=kem_pair.secret_b64(),
    )

    # Optionally generate DSA signing keys (not stored at all)
    if request.include_dsa:
        dsa_pair = generate_dsa_keypair()
        response.dsa_public_key_b64 = dsa_pair.public_b64()
        response.dsa_secret_key_b64 = dsa_pair.secret_b64()

    return response


@router.get("/", response_model=list[KeyResponse])
async def list_keys(db: AsyncSession = Depends(get_db)):
    """List all stored public keys."""
    result = await db.execute(select(VaultKey).order_by(VaultKey.created_at.desc()))
    keys = result.scalars().all()
    return [
        KeyResponse(
            key_id=k.id,
            name=k.name,
            algorithm=k.algorithm,
            public_key_b64=k.public_key_b64,
            created_at=k.created_at,
        )
        for k in keys
    ]


@router.get("/{key_id}", response_model=KeyResponse)
async def get_key(key_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve a specific key by ID."""
    key = await db.get(VaultKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found.")
    return KeyResponse(
        key_id=key.id,
        name=key.name,
        algorithm=key.algorithm,
        public_key_b64=key.public_key_b64,
        created_at=key.created_at,
    )

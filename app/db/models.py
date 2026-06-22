"""
app/db/models.py

SQLite database models using SQLAlchemy async.

Security note: Keys and file contents are NEVER stored in the database.
The DB only holds metadata and the KEM ciphertext (the encrypted DEK),
which is useless without the secret key.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, DateTime, LargeBinary, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class VaultKey(Base):
    """
    Stores a named ML-KEM public key.

    The corresponding secret key is NEVER stored here — it is the
    user's responsibility to keep it secure (e.g., a keyfile on disk).
    """
    __tablename__ = "vault_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class VaultEntry(Base):
    """
    Metadata record for an encrypted file stored in the vault.

    Stores:
      - original filename and size (for display)
      - path to the .pqcvault bundle on disk
      - kem_ciphertext: the encrypted DEK (useless without the secret key)
      - which key was used (FK to VaultKey.id)
    """
    __tablename__ = "vault_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    vault_path: Mapped[str] = mapped_column(String(512), nullable=False)
    key_id: Mapped[str] = mapped_column(String(36), nullable=False)  # refers to VaultKey.id
    kem_ciphertext_b64: Mapped[str] = mapped_column(Text, nullable=False)
    has_signature: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

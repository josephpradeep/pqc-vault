# PQC File Vault

A quantum-resistant secure file vault implementing NIST-standardised post-quantum cryptography (FIPS 203 / 204).

## Architecture

```
pqc-vault/
├── app/
│   ├── core/
│   │   ├── config.py          # Settings (pydantic-settings)
│   │   └── crypto_engine.py   # ← The heart of the project
│   ├── api/routes/
│   │   ├── keys.py            # POST /api/v1/keys/generate, GET /api/v1/keys/
│   │   └── vault.py           # POST /api/v1/vault/encrypt, POST /api/v1/vault/decrypt
│   ├── db/
│   │   ├── models.py          # VaultKey, VaultEntry (SQLAlchemy)
│   │   └── session.py         # Async engine + get_db dependency
│   ├── schemas/vault.py       # Pydantic v2 request/response models
│   └── main.py                # FastAPI app
├── cli/vault.py               # Typer CLI (keygen / encrypt / decrypt / info)
├── tests/test_crypto_engine.py
├── setup.sh                   # Fedora setup (liboqs + Python deps)
└── requirements.txt
```

## Cryptographic Design

### Hybrid scheme (why not PQC-only?)

ML-KEM (a Key Encapsulation Mechanism) is asymmetric — it's designed for key exchange, not bulk encryption. Encrypting large files directly with an asymmetric scheme would be impractically slow.

The solution is a **hybrid scheme**:

```
┌─────────────────────────────────────────────────────────────────┐
│ ENCRYPTION                                                      │
│                                                                 │
│  File bytes ──► AES-256-GCM ──► Ciphertext                     │
│                      ▲                                          │
│              Random DEK (32 bytes)                              │
│                      │                                          │
│  Recipient pubkey ──► ML-KEM-768.Encapsulate ──► KEM ciphertext│
│                                                                 │
│  Bundle = JSON header(kem_ciphertext, nonce) + raw ciphertext   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ DECRYPTION                                                      │
│                                                                 │
│  KEM ciphertext ──► ML-KEM-768.Decapsulate(secret_key) ──► DEK │
│  DEK + nonce ──► AES-256-GCM.Decrypt ──► Plaintext             │
└─────────────────────────────────────────────────────────────────┘
```

### Algorithms
| Role | Algorithm | Standard |
|------|-----------|----------|
| Key Encapsulation | ML-KEM-768 | NIST FIPS 203 |
| Digital Signature | ML-DSA-65 | NIST FIPS 204 |
| Symmetric Encryption | AES-256-GCM | NIST FIPS 197 |

### What the database stores
The database stores **metadata only**:
- Original filename, size, creation date
- Which public key was used
- The KEM ciphertext (the encrypted DEK)

**Secret keys are never stored.** The KEM ciphertext is useless without the secret key.

## Setup

```bash
chmod +x setup.sh
./setup.sh
source .venv/bin/activate
```

## Running the API

```bash
uvicorn app.main:app --reload
# Swagger UI: http://localhost:8000/docs
```

## CLI Usage

```bash
# Generate a key pair
python -m cli.vault keygen --name alice

# Encrypt a file
python -m cli.vault encrypt report.pdf --pub-key alice.kem.pub.b64

# Decrypt a file
python -m cli.vault decrypt report.pdf.pqcvault --sec-key alice.kem.sec.b64

# Inspect a vault bundle (no decryption)
python -m cli.vault info report.pdf.pqcvault

# With ML-DSA signing
python -m cli.vault keygen --name alice --with-dsa
python -m cli.vault encrypt report.pdf --pub-key alice.kem.pub.b64 --dsa-key alice.dsa.sec.b64
python -m cli.vault decrypt report.pdf.pqcvault --sec-key alice.kem.sec.b64 --dsa-pub alice.dsa.pub.b64
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/keys/generate` | Generate ML-KEM (+ optional ML-DSA) key pair |
| GET | `/api/v1/keys/` | List all stored public keys |
| GET | `/api/v1/keys/{key_id}` | Get a specific public key |
| POST | `/api/v1/vault/encrypt` | Encrypt and store a file |
| POST | `/api/v1/vault/decrypt` | Decrypt a vault entry |
| GET | `/api/v1/vault/` | List all vault entries |
| DELETE | `/api/v1/vault/{entry_id}` | Delete a vault entry |

## Running Tests

```bash
pytest tests/ -v
```

## Resume bullet point

> Engineered a quantum-resistant file vault in Python using FastAPI and `liboqs-python`, implementing a hybrid cryptographic protocol with NIST-standardised ML-KEM-768 (FIPS 203) for key encapsulation and AES-256-GCM for symmetric encryption, with optional ML-DSA-65 (FIPS 204) digital signatures — defending against harvest-now-decrypt-later attacks in a REST API + CLI architecture backed by SQLite metadata storage.

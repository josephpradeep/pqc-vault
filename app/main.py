"""
app/main.py
FastAPI application entrypoint.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import keys, vault
from app.core.config import settings
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create DB tables on startup."""
    await init_db()
    yield


app = FastAPI(
    title="PQC File Vault",
    description=(
        "A quantum-resistant secure file vault using hybrid cryptography. "
        "Implements ML-KEM-768 (FIPS 203) for key encapsulation and "
        "AES-256-GCM for symmetric file encryption. "
        "Optionally supports ML-DSA-65 (FIPS 204) digital signatures."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(keys.router, prefix="/api/v1")
app.include_router(vault.router, prefix="/api/v1")


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "PQC File Vault",
        "status": "operational",
        "kem_algorithm": settings.KEM_ALGORITHM,
        "dsa_algorithm": settings.DSA_ALGORITHM,
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}

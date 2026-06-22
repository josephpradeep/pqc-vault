"""
app/core/config.py
Application settings loaded from environment / .env file.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Storage
    VAULT_DIR: Path = Path("./vault_data")
    DATABASE_URL: str = "sqlite+aiosqlite:///./vault.db"

    # Security
    SECRET_KEY: str = "change-me-in-production-32-chars-min"

    # PQC Algorithm selection (NIST-standardised)
    KEM_ALGORITHM: str = "ML-KEM-768"   # Key Encapsulation Mechanism
    DSA_ALGORITHM: str = "ML-DSA-65"    # Digital Signature Algorithm

    # AES symmetric key size (bytes)
    AES_KEY_SIZE: int = 32  # 256-bit

    def model_post_init(self, __context):
        self.VAULT_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()

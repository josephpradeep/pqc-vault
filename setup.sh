#!/usr/bin/env bash
# PQC File Vault — Fedora Setup Script
# Run with: chmod +x setup.sh && ./setup.sh

set -e

echo "==> [1/6] Installing system dependencies..."
sudo dnf install -y \
    python3 python3-pip python3-venv \
    cmake gcc gcc-c++ make \
    openssl-devel libffi-devel \
    git curl

echo "==> [2/6] Cloning & building liboqs (Open Quantum Safe C library)..."
if [ ! -d "$HOME/liboqs" ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$HOME/liboqs"
fi
cd "$HOME/liboqs"
mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
make -j"$(nproc)"
sudo make install
sudo ldconfig
cd -

echo "==> [3/6] Setting up Python virtual environment..."
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate

echo "==> [4/6] Installing Python dependencies..."
pip install --upgrade pip
pip install \
    fastapi==0.111.0 \
    uvicorn[standard]==0.29.0 \
    python-multipart==0.0.9 \
    sqlalchemy==2.0.30 \
    aiosqlite==0.20.0 \
    cryptography==42.0.8 \
    liboqs-python==0.10.1 \
    typer==0.12.3 \
    rich==13.7.1 \
    pydantic==2.7.1 \
    pydantic-settings==2.2.1 \
    httpx==0.27.0 \
    pytest==8.2.0 \
    pytest-asyncio==0.23.7

echo "==> [5/6] Creating .env file..."
cat > .env << 'EOF'
VAULT_DIR=./vault_data
DATABASE_URL=sqlite+aiosqlite:///./vault.db
SECRET_KEY=change-me-in-production-32-chars-min
EOF

echo "==> [6/6] Done! Activate your environment with:"
echo "    source .venv/bin/activate"
echo ""
echo "Start the API server:  uvicorn app.main:app --reload"
echo "Use the CLI:           python -m cli.vault --help"

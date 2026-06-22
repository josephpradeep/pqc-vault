"""
cli/vault.py

PQC Vault CLI — interact with the crypto engine directly (no API required).

Usage:
    python -m cli.vault --help
    python -m cli.vault keygen --name mykey
    python -m cli.vault encrypt secret.pdf --key-file mykey.pub.b64
    python -m cli.vault decrypt secret.pdf.pqcvault --key-file mykey.sec.b64
    python -m cli.vault info secret.pdf.pqcvault
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.crypto_engine import (
    EncryptedBundle,
    generate_dsa_keypair,
    generate_kem_keypair,
    encrypt_file_path,
    decrypt_file_path,
)
from app.core.config import settings

app = typer.Typer(
    name="pqc-vault",
    help="[bold cyan]PQC File Vault[/bold cyan] — quantum-resistant file encryption CLI",
    rich_markup_mode="rich",
)
console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# keygen
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def keygen(
    name: str = typer.Option(..., "--name", "-n", help="Key name prefix for output files"),
    algorithm: str = typer.Option("ML-KEM-768", "--algorithm", "-a", help="KEM algorithm"),
    with_dsa: bool = typer.Option(False, "--with-dsa", help="Also generate ML-DSA signing keys"),
    output_dir: Path = typer.Option(Path("."), "--output", "-o", help="Output directory for key files"),
):
    """Generate ML-KEM (and optionally ML-DSA) key pairs and save to files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    with console.status(f"Generating [cyan]{algorithm}[/cyan] key pair..."):
        kem_pair = generate_kem_keypair(algorithm)

    pub_path = output_dir / f"{name}.kem.pub.b64"
    sec_path = output_dir / f"{name}.kem.sec.b64"
    pub_path.write_text(kem_pair.public_b64())
    sec_path.write_text(kem_pair.secret_b64())

    table = Table(title="Key files generated", show_header=True, header_style="bold")
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Keep secret?")
    table.add_row("KEM public key", str(pub_path), "[green]No — share freely[/green]")
    table.add_row("KEM secret key", str(sec_path), "[red bold]YES — never share[/red bold]")

    if with_dsa:
        with console.status("Generating [cyan]ML-DSA-65[/cyan] signing keys..."):
            dsa_pair = generate_dsa_keypair()

        dsa_pub_path = output_dir / f"{name}.dsa.pub.b64"
        dsa_sec_path = output_dir / f"{name}.dsa.sec.b64"
        dsa_pub_path.write_text(dsa_pair.public_b64())
        dsa_sec_path.write_text(dsa_pair.secret_b64())

        table.add_row("DSA public key", str(dsa_pub_path), "[green]No — share with verifiers[/green]")
        table.add_row("DSA secret key", str(dsa_sec_path), "[red bold]YES — never share[/red bold]")

    console.print(table)
    rprint(
        Panel.fit(
            "[yellow]⚠ Secret key files are not encrypted at rest.[/yellow]\n"
            "Consider storing them on an encrypted volume or hardware token.",
            title="Security reminder",
            border_style="yellow",
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# encrypt
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def encrypt(
    input_file: Path = typer.Argument(..., help="File to encrypt"),
    pub_key_file: Path = typer.Option(..., "--pub-key", "-k", help="Path to .kem.pub.b64 file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output path (default: <input>.pqcvault)"),
    dsa_sec_key_file: Optional[Path] = typer.Option(None, "--dsa-key", help="ML-DSA secret key file for signing"),
):
    """Encrypt a file using hybrid ML-KEM + AES-256-GCM encryption."""
    if not input_file.exists():
        rprint(f"[red]Error: File not found: {input_file}[/red]")
        raise typer.Exit(1)

    if not pub_key_file.exists():
        rprint(f"[red]Error: Public key file not found: {pub_key_file}[/red]")
        raise typer.Exit(1)

    kem_public_key = base64.b64decode(pub_key_file.read_text().strip())
    dsa_secret_key = None
    if dsa_sec_key_file:
        if not dsa_sec_key_file.exists():
            rprint(f"[red]Error: DSA secret key file not found: {dsa_sec_key_file}[/red]")
            raise typer.Exit(1)
        dsa_secret_key = base64.b64decode(dsa_sec_key_file.read_text().strip())

    dest = output or input_file.with_suffix(input_file.suffix + ".pqcvault")

    with console.status(f"Encrypting [cyan]{input_file.name}[/cyan]..."):
        bundle = encrypt_file_path(
            input_file,
            dest,
            kem_public_key=kem_public_key,
            dsa_secret_key=dsa_secret_key,
        )

    size_in = input_file.stat().st_size
    size_out = dest.stat().st_size

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold dim")
    table.add_column()
    table.add_row("Input:", str(input_file))
    table.add_row("Output:", str(dest))
    table.add_row("KEM:", bundle.kem_algorithm)
    table.add_row("Symmetric:", "AES-256-GCM")
    table.add_row("Signed:", "Yes (ML-DSA-65)" if bundle.signature else "No")
    table.add_row("Input size:", f"{size_in:,} bytes")
    table.add_row("Output size:", f"{size_out:,} bytes")

    console.print(Panel(table, title="[green]✓ Encrypted[/green]", border_style="green"))


# ─────────────────────────────────────────────────────────────────────────────
# decrypt
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def decrypt(
    input_file: Path = typer.Argument(..., help=".pqcvault file to decrypt"),
    sec_key_file: Path = typer.Option(..., "--sec-key", "-k", help="Path to .kem.sec.b64 file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output path (default: strips .pqcvault)"),
    dsa_pub_key_file: Optional[Path] = typer.Option(None, "--dsa-pub", help="ML-DSA public key for signature verification"),
):
    """Decrypt a .pqcvault file using the ML-KEM secret key."""
    if not input_file.exists():
        rprint(f"[red]Error: Vault file not found: {input_file}[/red]")
        raise typer.Exit(1)

    if not sec_key_file.exists():
        rprint(f"[red]Error: Secret key file not found: {sec_key_file}[/red]")
        raise typer.Exit(1)

    kem_secret_key = base64.b64decode(sec_key_file.read_text().strip())
    dsa_public_key = None
    if dsa_pub_key_file:
        if not dsa_pub_key_file.exists():
            rprint(f"[red]Error: DSA public key file not found: {dsa_pub_key_file}[/red]")
            raise typer.Exit(1)
        dsa_public_key = base64.b64decode(dsa_pub_key_file.read_text().strip())

    # Determine output path
    if output is None:
        name = input_file.name
        if name.endswith(".pqcvault"):
            output = input_file.with_name(name[: -len(".pqcvault")])
        else:
            output = input_file.with_suffix(".decrypted")

    with console.status(f"Decrypting [cyan]{input_file.name}[/cyan]..."):
        try:
            decrypt_file_path(
                input_file,
                output,
                kem_secret_key=kem_secret_key,
                dsa_public_key=dsa_public_key,
            )
        except ValueError as exc:
            rprint(Panel(f"[red]{exc}[/red]", title="[red]✗ Decryption failed[/red]", border_style="red"))
            raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold]Output:[/bold] {output}\n[bold]Size:[/bold] {output.stat().st_size:,} bytes",
            title="[green]✓ Decrypted[/green]",
            border_style="green",
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# info — inspect a bundle without decrypting
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def info(
    vault_file: Path = typer.Argument(..., help=".pqcvault file to inspect"),
):
    """Show metadata about a .pqcvault bundle without decrypting it."""
    if not vault_file.exists():
        rprint(f"[red]Error: File not found: {vault_file}[/red]")
        raise typer.Exit(1)

    raw = vault_file.read_bytes()
    bundle = EncryptedBundle.from_bytes(raw)

    sep = raw.index(b"\n")
    header_size = sep + 1
    ciphertext_size = len(raw) - header_size

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold dim")
    table.add_column()
    table.add_row("Format version:", bundle.version)
    table.add_row("KEM algorithm:", bundle.kem_algorithm)
    table.add_row("Symmetric cipher:", "AES-256-GCM")
    table.add_row("KEM ciphertext size:", f"{len(bundle.kem_ciphertext):,} bytes")
    table.add_row("AES nonce:", bundle.aes_nonce.hex())
    table.add_row("Ciphertext size:", f"{ciphertext_size:,} bytes")
    table.add_row("Has signature:", "Yes" if bundle.signature else "No")
    if bundle.signature:
        table.add_row("DSA algorithm:", bundle.dsa_algorithm or "unknown")

    console.print(Panel(table, title=f"[cyan]Bundle info: {vault_file.name}[/cyan]", border_style="cyan"))


if __name__ == "__main__":
    app()

import os
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.config import ENCRYPTED_DIR, ensure_directories
from src.database.connection import db_session
from src.core.audit import log_action

SALT_SIZE = 16
NONCE_SIZE = 12
HEADER_SIZE = SALT_SIZE + NONCE_SIZE
ITERATIONS = 100_000


def _derive_aes256_key(passphrase: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES 256-bit (32 byte) dari passphrase pengguna."""
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    ).derive(passphrase.encode())


def encrypt_document(doc_id: int, passphrase: str, user_id: int) -> dict[str, Any]:
    """Mengenkripsi berkas dokumen dengan AES-256-GCM dan menyimpannya sebagai .seal."""
    ensure_directories()

    with db_session() as conn:
        if not (doc := conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()):
            raise ValueError(f"Dokumen ID {doc_id} tidak ditemukan.")

        source_path = Path(doc["file_path"])
        if not source_path.exists():
            raise FileNotFoundError(f"File fisik tidak ditemukan: {source_path}")

        salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(_derive_aes256_key(passphrase, salt)).encrypt(
            nonce, source_path.read_bytes(), None
        )

        seal_filename = f"{source_path.stem}_v{doc['version']}.seal"
        encrypted_path = ENCRYPTED_DIR / seal_filename
        encrypted_path.write_bytes(salt + nonce + ciphertext)
        conn.execute("UPDATE documents SET is_encrypted = 1 WHERE doc_id = ?", (doc_id,))

    log_action(
        user_id,
        "ENCRYPT",
        "SUCCESS",
        doc_id=doc_id,
        details=f"Terenkripsi dengan AES-256-GCM ke {seal_filename}",
    )
    return {
        "doc_id": doc_id,
        "encrypted_file": str(encrypted_path),
        "message": f"Dokumen berhasil dikunci: {seal_filename}",
    }


def decrypt_document(
    encrypted_path: str | Path,
    passphrase: str,
    output_path: str | Path,
    user_id: int,
    doc_id: int | None = None,
) -> dict[str, Any]:
    """Mendekripsi berkas .seal kembali ke bentuk file asli."""
    enc_path = Path(encrypted_path)
    if not enc_path.exists():
        raise FileNotFoundError(f"File terenkripsi tidak ditemukan: {enc_path}")

    raw_data = enc_path.read_bytes()
    if len(raw_data) <= HEADER_SIZE:
        raise ValueError("Format file .seal rusak atau tidak valid.")

    salt, nonce, ciphertext = (
        raw_data[:SALT_SIZE],
        raw_data[SALT_SIZE:HEADER_SIZE],
        raw_data[HEADER_SIZE:],
    )

    try:
        plaintext = AESGCM(_derive_aes256_key(passphrase, salt)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        log_action(
            user_id,
            "DECRYPT",
            "FAILED_INVALID_KEY",
            doc_id=doc_id,
            details=f"Gagal dekripsi {enc_path.name}: Passphrase salah atau file korup",
        )
        raise ValueError("Dekripsi gagal! Passphrase salah atau file telah dimodifikasi.") from exc

    out_path = Path(output_path)
    out_path.write_bytes(plaintext)

    log_action(
        user_id,
        "DECRYPT",
        "SUCCESS",
        doc_id=doc_id,
        details=f"Berhasil dekripsi {enc_path.name} ke {out_path.name}",
    )
    return {
        "output_file": str(out_path),
        "message": f"Dokumen berhasil didekripsi ke: {out_path}",
    }

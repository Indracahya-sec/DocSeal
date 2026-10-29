import os
from pathlib import Path
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from src.config import ENCRYPTED_DIR, ensure_directories
from src.database.connection import get_db_connection
from src.core.audit import log_action

SALT_SIZE = 16  # 128-bit salt
NONCE_SIZE = 12  # 96-bit nonce standar GCM
ITERATIONS = 100_000


def _derive_aes256_key(passphrase: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES 256-bit (32 byte) dari passphrase pengguna."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits (AES-256)
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_document(doc_id: int, passphrase: str, user_id: int) -> Dict[str, Any]:
    """Mengenkripsi berkas dokumen dengan AES-256-GCM dan menyimpannya sebagai .seal."""
    ensure_directories()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,))
    doc = cursor.fetchone()

    if not doc:
        conn.close()
        raise ValueError(f"Dokumen ID {doc_id} tidak ditemukan.")

    source_path = Path(doc["file_path"])
    if not source_path.exists():
        conn.close()
        raise FileNotFoundError(f"File fisik tidak ditemukan: {source_path}")

    # Baca isi file asli
    plaintext = source_path.read_bytes()

    # Bangkitkan Salt (16B) & Nonce (12B) acak kriptografis
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_aes256_key(passphrase, salt)

    # Enkripsi menggunakan AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Simpan dengan struktur biner: [SALT 16B][NONCE 12B][CIPHERTEXT + GCM TAG]
    seal_filename = f"{source_path.stem}_v{doc['version']}.seal"
    encrypted_path = ENCRYPTED_DIR / seal_filename
    encrypted_path.write_bytes(salt + nonce + ciphertext)

    # Tandai status dokumen terenkripsi di database
    cursor.execute("UPDATE documents SET is_encrypted = 1 WHERE doc_id = ?", (doc_id,))
    conn.commit()
    conn.close()

    log_action(
        user_id=user_id,
        action="ENCRYPT",
        doc_id=doc_id,
        status_result="SUCCESS",
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
) -> Dict[str, Any]:
    """Mendekripsi berkas .seal kembali ke bentuk file asli."""
    enc_path = Path(encrypted_path)
    if not enc_path.exists():
        raise FileNotFoundError(f"File terenkripsi tidak ditemukan: {enc_path}")

    raw_data = enc_path.read_bytes()
    if len(raw_data) <= (SALT_SIZE + NONCE_SIZE):
        raise ValueError("Format file .seal rusak atau tidak valid.")

    # Ekstrak Salt, Nonce, dan Ciphertext dari header file .seal
    salt = raw_data[:SALT_SIZE]
    nonce = raw_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = raw_data[SALT_SIZE + NONCE_SIZE :]

    key = _derive_aes256_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        log_action(
            user_id=user_id,
            action="DECRYPT",
            doc_id=doc_id,
            status_result="FAILED_INVALID_KEY",
            details=f"Gagal dekripsi {enc_path.name}: Passphrase salah atau file korup",
        )
        raise ValueError(
            "Dekripsi gagal! Passphrase salah atau file telah dimodifikasi."
        )

    out_path = Path(output_path)
    out_path.write_bytes(plaintext)

    log_action(
        user_id=user_id,
        action="DECRYPT",
        doc_id=doc_id,
        status_result="SUCCESS",
        details=f"Berhasil dekripsi {enc_path.name} ke {out_path.name}",
    )

    return {
        "output_file": str(out_path),
        "message": f"Dokumen berhasil didekripsi ke: {out_path}",
    }

import hashlib
from pathlib import Path
from typing import Dict, Any
from src.database.connection import get_db_connection
from src.core.audit import log_action


def calculate_sha256(file_path: str | Path) -> str:
    """Menghitung fingerprint SHA-256 file secara bertahap (chunk 4KB)."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Berkas tidak ditemukan: {path}")

    sha256_Engine = hashlib.sha256()
    with open(path, "rb") as f:
        # Membaca per 4096 bytes agar hemat RAM meskipun file berukuran besar
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_Engine.update(byte_block)

    return sha256_Engine.hexdigest()


def register_document(
    file_path: str | Path, doc_name: str, user_id: int
) -> Dict[str, Any]:
    """
    Mendaftarkan dokumen ke database sekaligus mengecek:
    1. Apakah file 100% duplikat identik?
    2. Apakah file merupakan revisi baru dari dokumen yang sudah ada?
    """
    file_hash = calculate_sha256(file_path)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Skenario 1: Cek Duplikat Fisik (Apakah nilai hash sudah ada di DB?)
    cursor.execute("SELECT * FROM documents WHERE sha256_hash = ?", (file_hash,))
    duplicate = cursor.fetchone()
    if duplicate:
        conn.close()
        log_action(
            user_id=user_id,
            action="UPLOAD",
            doc_id=duplicate["doc_id"],
            status_result="DUPLICATE_REJECTED",
            details=f"File identik dengan {duplicate['doc_name']} (v{duplicate['version']})",
        )
        return {
            "status": "DUPLICATE",
            "message": f"Ditolak! Isi file 100% identik dengan '{duplicate['doc_name']}' versi v{duplicate['version']}.",
            "sha256": file_hash,
        }

    # Skenario 2: Cek Versioning (Apakah doc_name sudah ada tapi isinya/hash berbeda?)
    cursor.execute(
        "SELECT MAX(version) as latest_ver FROM documents WHERE doc_name = ?",
        (doc_name,),
    )
    row = cursor.fetchone()
    new_version = (
        (row["latest_ver"] + 1) if (row and row["latest_ver"] is not None) else 1
    )

    # Simpan dokumen baru atau versi revisi ke database
    cursor.execute(
        """
        INSERT INTO documents (doc_name, file_path, sha256_hash, version, uploaded_by)
        VALUES (?, ?, ?, ?, ?)
        """,
        (doc_name, str(file_path), file_hash, new_version, user_id),
    )
    doc_id = cursor.lastrowid
    conn.commit()
    conn.close()

    action_status = "NEW_VERSION" if new_version > 1 else "NEW_DOCUMENT"
    log_action(
        user_id=user_id,
        action="UPLOAD",
        doc_id=doc_id,
        status_result=action_status,
        details=f"Terdaftar sebagai {doc_name} v{new_version}",
    )

    return {
        "status": action_status,
        "doc_id": doc_id,
        "version": new_version,
        "sha256": file_hash,
        "message": f"Berhasil disimpan sebagai {doc_name} (v{new_version})",
    }


def verify_document_integrity(
    doc_id: int, target_file_path: str | Path, user_id: int
) -> Dict[str, Any]:
    """Membandingkan hash file saat ini dengan hash asli di database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,))
    doc = cursor.fetchone()
    conn.close()

    if not doc:
        raise ValueError(f"Dokumen dengan ID {doc_id} tidak ditemukan di database.")

    current_hash = calculate_sha256(target_file_path)
    expected_hash = doc["sha256_hash"]
    is_valid = current_hash == expected_hash

    status_str = "VALID" if is_valid else "MODIFIED"
    log_action(
        user_id=user_id,
        action="VERIFY",
        doc_id=doc_id,
        status_result=status_str,
        details=f"Hash cocok"
        if is_valid
        else f"Mismatch! DB: {expected_hash[:10]}... vs File: {current_hash[:10]}...",
    )

    return {
        "doc_id": doc_id,
        "doc_name": doc["doc_name"],
        "version": doc["version"],
        "is_valid": is_valid,
        "status": status_str,
        "expected_hash": expected_hash,
        "current_hash": current_hash,
    }

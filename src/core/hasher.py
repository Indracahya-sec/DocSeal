from collections import Counter
import hashlib
from pathlib import Path
from typing import Any
from src.database.connection import db_session
from src.core.audit import log_action


def calculate_sha256(file_path: str | Path) -> str:
    """Menghitung fingerprint SHA-256 file secara bertahap (chunk 4KB)."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Berkas tidak ditemukan: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(4096):
            digest.update(chunk)
    return digest.hexdigest()


def register_document(
    file_path: str | Path, doc_name: str, user_id: int
) -> dict[str, Any]:
    """Mendaftarkan dokumen ke database sekaligus menangani deduplikasi dan auto-versioning."""
    file_hash = calculate_sha256(file_path)

    with db_session() as conn:
        if dup := conn.execute(
            "SELECT * FROM documents WHERE sha256_hash = ?", (file_hash,)
        ).fetchone():
            dup_data = dict(dup)
        else:
            dup_data = None
            (new_version,) = conn.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM documents WHERE doc_name = ?",
                (doc_name,),
            ).fetchone()
            doc_id = conn.execute(
                "INSERT INTO documents (doc_name, file_path, sha256_hash, version, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                (doc_name, str(file_path), file_hash, new_version, user_id),
            ).lastrowid

    if dup_data:
        log_action(
            user_id,
            "UPLOAD",
            "DUPLICATE_REJECTED",
            doc_id=dup_data["doc_id"],
            details=f"File identik dengan {dup_data['doc_name']} (v{dup_data['version']})",
        )
        return {
            "status": "DUPLICATE",
            "message": f"Ditolak! Isi file 100% identik dengan '{dup_data['doc_name']}' versi v{dup_data['version']}.",
            "sha256": file_hash,
        }

    status = "NEW_VERSION" if new_version > 1 else "NEW_DOCUMENT"
    log_action(
        user_id,
        "UPLOAD",
        status,
        doc_id=doc_id,
        details=f"Terdaftar sebagai {doc_name} v{new_version}",
    )
    return {
        "status": status,
        "doc_id": doc_id,
        "version": new_version,
        "sha256": file_hash,
        "message": f"Berhasil disimpan sebagai {doc_name} (v{new_version})",
    }


def verify_document_integrity(
    doc_id: int, target_file_path: str | Path, user_id: int
) -> dict[str, Any]:
    """Membandingkan hash file saat ini dengan hash asli di database."""
    with db_session() as conn:
        if not (doc := conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()):
            raise ValueError(f"Dokumen dengan ID {doc_id} tidak ditemukan di database.")

    expected_hash = doc["sha256_hash"]
    current_hash = calculate_sha256(target_file_path)
    is_valid = current_hash == expected_hash
    status = "VALID" if is_valid else "MODIFIED"

    log_action(
        user_id,
        "VERIFY",
        status,
        doc_id=doc_id,
        details="Hash cocok" if is_valid else f"Mismatch! DB: {expected_hash[:10]}... vs File: {current_hash[:10]}...",
    )
    return {
        "doc_id": doc_id,
        "doc_name": doc["doc_name"],
        "version": doc["version"],
        "is_valid": is_valid,
        "status": status,
        "expected_hash": expected_hash,
        "current_hash": current_hash,
    }


def _inspect_doc_row(doc: Any) -> dict[str, Any]:
    """Memeriksa keberadaan dan kecocokan hash satu baris dokumen di disk."""
    fpath, expected = Path(doc["file_path"]), doc["sha256_hash"]
    if not fpath.exists():
        current, status = "-", "MISSING"
    else:
        current = calculate_sha256(fpath)
        status = "VALID" if current == expected else "MODIFIED"

    return {
        "doc_id": doc["doc_id"],
        "doc_name": doc["doc_name"],
        "version": doc["version"],
        "file_path": str(fpath),
        "expected_hash": expected,
        "current_hash": current,
        "status": status,
    }


def scan_all_documents_integrity(user_id: int) -> dict[str, Any]:
    """Memindai integritas seluruh berkas dokumen terdaftar secara otomatis (Batch Scan)."""
    with db_session() as conn:
        docs = conn.execute("SELECT * FROM documents ORDER BY doc_id ASC").fetchall()

    results = [_inspect_doc_row(doc) for doc in docs]
    counts = Counter(item["status"] for item in results)
    valid_count, modified_count, missing_count = counts["VALID"], counts["MODIFIED"], counts["MISSING"]
    overall_status = "ALL_VALID" if not (modified_count or missing_count) else "ANOMALY_DETECTED"

    log_action(
        user_id,
        "BATCH_SCAN",
        overall_status,
        details=f"Total: {len(results)} | Valid: {valid_count} | Modified: {modified_count} | Missing: {missing_count}",
    )
    return {
        "total": len(results),
        "valid_count": valid_count,
        "modified_count": modified_count,
        "missing_count": missing_count,
        "overall_status": overall_status,
        "results": results,
    }

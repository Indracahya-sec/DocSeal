import io
import sqlite3
from pathlib import Path

import pytest

from src.config import resolve_safe_path
from src.core.audit import export_audit_logs_csv
from src.core.hasher import (
    register_document,
    scan_all_documents_integrity,
    validate_pdf_stream,
)
from src.core.rbac import (
    authenticate_user,
    create_user,
    has_permission,
    is_account_locked,
    list_users,
)
from src.database.connection import get_db_connection
from src.database.seed import seed_database
from src.web.app import app
from tests.generate_dummy import create_custom_pdf


@pytest.fixture
def full_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Menyiapkan environment database dan direktori penyimpanan terisolasi."""
    test_db = tmp_path / "test_docseal.db"
    test_dummy_dir = tmp_path / "dummy_docs"
    test_enc_dir = tmp_path / "encrypted"
    test_dummy_dir.mkdir(parents=True, exist_ok=True)
    test_enc_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("src.database.connection.DB_PATH", test_db)
    monkeypatch.setattr("src.core.crypto.ENCRYPTED_DIR", test_enc_dir)
    monkeypatch.setattr("src.core.audit.DATA_DIR", tmp_path)
    monkeypatch.setattr("src.web.app.DATA_DIR", tmp_path)
    monkeypatch.setattr("src.web.app.DUMMY_DIR", test_dummy_dir)
    monkeypatch.setattr("src.web.app.ENCRYPTED_DIR", test_enc_dir)
    seed_database()
    app.config["TESTING"] = True
    return tmp_path


def test_rbac_authentication_and_user_management(full_env: Path):
    admin = authenticate_user("admin", "admin123")
    assert admin is not None
    assert admin["role"] == "admin"

    failed = authenticate_user("admin", "password_salah")
    assert failed is None

    assert has_permission("admin", "MANAGE_USERS") is True
    assert has_permission("operator", "UPLOAD") is True
    assert has_permission("operator", "MANAGE_USERS") is False
    assert has_permission("staf", "VERIFY") is True
    assert has_permission("staf", "ENCRYPT") is False
    assert has_permission("auditor", "VIEW_LOGS") is True
    assert has_permission("auditor", "DECRYPT") is False

    new_u = create_user("staf_baru", "rahasia123", "staf", actor_user_id=admin["user_id"])
    assert new_u["username"] == "staf_baru"
    assert len(list_users()) == 5

    with pytest.raises(ValueError, match="sudah terdaftar"):
        create_user("staf_baru", "rahasia123", "staf", actor_user_id=admin["user_id"])


def test_immutable_audit_log_triggers(full_env: Path):
    authenticate_user("staf", "staf123")

    conn = get_db_connection()
    row = conn.execute("SELECT log_id FROM audit_logs LIMIT 1").fetchone()
    assert row is not None

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE audit_logs SET action = 'HACKED' WHERE log_id = ?", (row["log_id"],))

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("DELETE FROM audit_logs WHERE log_id = ?", (row["log_id"],))
    conn.close()


def test_web_ui_versioning_encrypt_decrypt_and_rbac(full_env: Path):
    client = app.test_client()

    res_login = client.post("/login", data={"username": "operator", "password": "operator123"}, follow_redirects=True)
    assert res_login.status_code == 200

    pdf_v1 = b"%PDF-1.4 ISI_VERSI_1"
    pdf_v2 = b"%PDF-1.4 ISI_VERSI_2_REVISI"

    client.post(
        "/upload",
        data={"doc_name": "Berkas_Tes", "file": (io.BytesIO(pdf_v1), "berkas.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    client.post(
        "/upload",
        data={"doc_name": "Berkas_Tes", "file": (io.BytesIO(pdf_v2), "berkas.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    res_ver = client.post(
        "/verify",
        data={"doc_id": 1, "file": (io.BytesIO(pdf_v1), "uji.pdf")},
        content_type="multipart/form-data",
    )
    assert b"VALID (DOKUMEN ASLI / UTUH)" in res_ver.data

    client.post("/encrypt", data={"doc_id": 1, "passphrase": "kunci_web_123"}, follow_redirects=True)
    res_dec = client.post("/decrypt", data={"doc_id": 1, "passphrase": "kunci_web_123"})
    assert res_dec.status_code == 200
    assert res_dec.data == pdf_v1

    client.get("/logout")
    client.post("/login", data={"username": "staf", "password": "staf123"}, follow_redirects=True)
    res_seal = client.get("/download-seal/1", follow_redirects=True)
    assert b"Akses Ditolak" in res_seal.data


def test_batch_scan_export_csv_and_bruteforce_lockout(full_env: Path):
    f_doc = full_env / "dummy_docs" / "arsip_penting.pdf"
    f_doc.write_bytes(b"%PDF-1.4 DATA_ARSIP_ASLI")
    register_document(f_doc, "Arsip_Penting", user_id=2)

    scan_ok = scan_all_documents_integrity(user_id=3)
    assert scan_ok["overall_status"] == "ALL_VALID"
    assert scan_ok["valid_count"] == 1

    f_doc.write_bytes(b"%PDF-1.4 DATA_ARSIP_DIPALSUKAN_DI_DISK")
    scan_bad = scan_all_documents_integrity(user_id=3)
    assert scan_bad["overall_status"] == "ANOMALY_DETECTED"
    assert scan_bad["modified_count"] == 1

    csv_path = full_env / "audit_export.csv"
    csv_text = export_audit_logs_csv(actor_user_id=4, output_path=csv_path)
    assert csv_path.exists()
    assert "BATCH_SCAN" in csv_text
    assert "ANOMALY_DETECTED" in csv_text

    for _ in range(5):
        assert authenticate_user("auditor", "salah_terus") is None

    assert is_account_locked("auditor") is True
    assert authenticate_user("auditor", "auditor123") is None


def test_custom_dummy_pdf_generator(full_env: Path):
    out_pdf = create_custom_pdf(
        filename="Surat Tugas Tabanan",
        content="Nama: I Wayan Dummy\nKeterangan: Petugas Kloter 05",
        output_dir=full_env / "dummy_docs",
    )
    assert out_pdf.exists()
    assert out_pdf.name == "Surat_Tugas_Tabanan.pdf"
    assert out_pdf.read_bytes().startswith(b"%PDF-")

    client = app.test_client()
    client.post("/login", data={"username": "operator", "password": "operator123"})
    res = client.post(
        "/generate-dummy",
        data={
            "doc_name": "Rekomendasi_Paspor_01",
            "content": "Isi surat rekomendasi paspor jamaah dummy.",
            "mode": "register",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Rekomendasi_Paspor_01" in res.data


def test_security_validation_pdf_header_and_path_sanitization(full_env: Path):
    # 1. Tolak file palsu yang tidak memiliki header 5-byte %PDF-
    fake_stream = io.BytesIO(b"MZ_FAKE_EXECUTABLE_CONTENT")
    with pytest.raises(ValueError, match="Header 5-byte pertama bukan dokumen PDF valid"):
        validate_pdf_stream(fake_stream)

    # 2. Tolak file yang melampaui batas ukuran memori (Anti-DoS)
    oversized_stream = io.BytesIO(b"%PDF-" + b"A" * 100)
    with pytest.raises(ValueError, match="melebihi batas keamanan maksimum"):
        validate_pdf_stream(oversized_stream, max_size=32)

    # 3. Pastikan Path Sanitization mengisolasi file tetap di dalam direktori data/
    safe_resolved = resolve_safe_path("../../etc/passwd.pdf", target_dir=full_env / "dummy_docs", root_dir=full_env)
    assert safe_resolved.parent == (full_env / "dummy_docs").resolve()
    assert safe_resolved.name == "passwd.pdf"

    with pytest.raises(ValueError):
        resolve_safe_path("..", target_dir=full_env / "dummy_docs", root_dir=full_env)


def test_partner_ready_features_password_cert_and_backup(full_env: Path):
    sample_pdf = full_env / "dummy_docs" / "Sample_Mitra.pdf"
    sample_pdf.write_bytes(b"%PDF-1.4 Dokumen Resmi Kemenhaj Tabanan")
    reg = register_document(sample_pdf, "Berkas_Jamaah_Tabanan", user_id=1)

    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})

    # 1. Cetak Berita Acara Verifikasi (PDF)
    cert_res = client.post(
        "/verify/certificate",
        data={
            "doc_id": reg["doc_id"],
            "current_hash": reg["sha256"],
        },
    )
    assert cert_res.status_code == 200
    assert cert_res.data.startswith(b"%PDF-")

    # 2. Unduh Paket Backup Sistem (.ZIP) oleh Admin
    backup_res = client.get("/admin/backup")
    assert backup_res.status_code == 200
    assert backup_res.mimetype == "application/zip"
    assert backup_res.data.startswith(b"PK")

    # 3. Ganti Password Mandiri via Web UI
    pwd_res = client.post(
        "/users/change-password",
        data={"old_password": "admin123", "new_password": "admin_tabanan_2026"},
        follow_redirects=True,
    )
    assert pwd_res.status_code == 200
    assert b"berhasil diperbarui" in pwd_res.data
    assert authenticate_user("admin", "admin_tabanan_2026") is not None

import io
import sqlite3
import pytest
from pathlib import Path
from src.database.connection import get_db_connection
from src.database.seed import seed_database
from src.core.audit import export_audit_logs_csv
from src.core.rbac import authenticate_user, has_permission, create_user, list_users, is_account_locked
from src.core.hasher import register_document, scan_all_documents_integrity
from src.web.app import app


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
    monkeypatch.setattr("src.web.app.DATA_DIR", tmp_path)
    monkeypatch.setattr("src.web.app.DUMMY_DIR", test_dummy_dir)
    monkeypatch.setattr("src.web.app.ENCRYPTED_DIR", test_enc_dir)
    seed_database()
    app.config["TESTING"] = True
    return tmp_path


def test_rbac_authentication_and_user_management(full_env: Path):
    # 1. Uji autentikasi berhasil dan gagal
    admin = authenticate_user("admin", "admin123")
    assert admin is not None
    assert admin["role"] == "admin"

    failed = authenticate_user("admin", "password_salah")
    assert failed is None

    # 2. Uji matriks izin 4 role
    assert has_permission("admin", "MANAGE_USERS") is True
    assert has_permission("operator", "UPLOAD") is True
    assert has_permission("operator", "MANAGE_USERS") is False
    assert has_permission("staf", "VERIFY") is True
    assert has_permission("staf", "ENCRYPT") is False
    assert has_permission("auditor", "VIEW_LOGS") is True
    assert has_permission("auditor", "DECRYPT") is False

    # 3. Uji pembuatan user baru oleh Admin
    new_u = create_user("staf_baru", "rahasia123", "staf", actor_user_id=admin["user_id"])
    assert new_u["username"] == "staf_baru"
    assert len(list_users()) == 5

    # Duplikat username wajib ditolak
    with pytest.raises(ValueError, match="sudah terdaftar"):
        create_user("staf_baru", "rahasia123", "staf", actor_user_id=admin["user_id"])


def test_immutable_audit_log_triggers(full_env: Path):
    # Buat satu entri log lewat autentikasi
    authenticate_user("staf", "staf123")

    conn = get_db_connection()
    row = conn.execute("SELECT log_id FROM audit_logs LIMIT 1").fetchone()
    assert row is not None

    # Upaya UPDATE dan DELETE pada audit_logs wajib diblokir oleh SQLite Trigger
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE audit_logs SET action = 'HACKED' WHERE log_id = ?", (row["log_id"],))

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("DELETE FROM audit_logs WHERE log_id = ?", (row["log_id"],))
    conn.close()


def test_web_ui_versioning_encrypt_decrypt_and_rbac(full_env: Path):
    client = app.test_client()

    # 1. Login sebagai Operator
    res_login = client.post("/login", data={"username": "operator", "password": "operator123"}, follow_redirects=True)
    assert res_login.status_code == 200

    # 2. Upload v1 dan v2 dengan nama file fisik yang SAMA (memastikan v1 tidak tertimpa oleh v2)
    client.post(
        "/upload",
        data={"doc_name": "Berkas_Tes", "file": (io.BytesIO(b"ISI_VERSI_1"), "berkas.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    client.post(
        "/upload",
        data={"doc_name": "Berkas_Tes", "file": (io.BytesIO(b"ISI_VERSI_2_REVISI"), "berkas.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    # Verifikasi bahwa v1 masih VALID terhadap b"ISI_VERSI_1" (tidak tertimpa oleh v2)
    res_ver = client.post(
        "/verify",
        data={"doc_id": 1, "file": (io.BytesIO(b"ISI_VERSI_1"), "uji.pdf")},
        content_type="multipart/form-data",
    )
    assert b"VALID (DOKUMEN ASLI / UTUH)" in res_ver.data

    # 3. Enkripsi dokumen v1 dan Dekripsi via Web UI
    client.post("/encrypt", data={"doc_id": 1, "passphrase": "kunci_web_123"}, follow_redirects=True)
    res_dec = client.post("/decrypt", data={"doc_id": 1, "passphrase": "kunci_web_123"})
    assert res_dec.status_code == 200
    assert res_dec.data == b"ISI_VERSI_1"

    # 4. Login sebagai Staf: tidak boleh bisa mengunduh .seal atau membuat user
    client.get("/logout")
    client.post("/login", data={"username": "staf", "password": "staf123"}, follow_redirects=True)
    res_seal = client.get("/download-seal/1", follow_redirects=True)
    assert b"Akses Ditolak" in res_seal.data


def test_batch_scan_export_csv_and_bruteforce_lockout(full_env: Path):
    # 1. Uji Batch Integrity Scan (kondisi normal & kondisi file dirusak langsung di disk)
    f_doc = full_env / "dummy_docs" / "arsip_penting.pdf"
    f_doc.write_bytes(b"DATA_ARSIP_ASLI")
    register_document(f_doc, "Arsip_Penting", user_id=2)

    scan_ok = scan_all_documents_integrity(user_id=3)
    assert scan_ok["overall_status"] == "ALL_VALID"
    assert scan_ok["valid_count"] == 1

    # Simulasi perusakan langsung di disk (Direct Disk Tampering)
    f_doc.write_bytes(b"DATA_ARSIP_DIPALSUKAN_DI_DISK")
    scan_bad = scan_all_documents_integrity(user_id=3)
    assert scan_bad["overall_status"] == "ANOMALY_DETECTED"
    assert scan_bad["modified_count"] == 1

    # 2. Uji Ekspor Audit Trail CSV
    csv_path = full_env / "audit_export.csv"
    csv_text = export_audit_logs_csv(actor_user_id=4, output_path=csv_path)
    assert csv_path.exists()
    assert "BATCH_SCAN" in csv_text
    assert "ANOMALY_DETECTED" in csv_text

    # 3. Uji Proteksi Brute-Force (5x gagal login beruntun mengunci akun)
    for _ in range(5):
        assert authenticate_user("auditor", "salah_terus") is None

    assert is_account_locked("auditor") is True
    # Bahkan dengan password benar pun akan ditolak saat sedang terkunci
    assert authenticate_user("auditor", "auditor123") is None


import pytest
from pathlib import Path
from src.database.seed import seed_database
from src.core.hasher import (
    calculate_sha256,
    register_document,
    verify_document_integrity,
)


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Membuat database SQLite sementara agar pengujian tidak mengotori data asli."""
    test_db = tmp_path / "test_docseal.db"
    monkeypatch.setattr("src.database.connection.DB_PATH", test_db)
    seed_database()
    return tmp_path


def test_sha256_and_document_lifecycle(isolated_env: Path):
    # 1. Buat file dummy asli
    file_v1 = isolated_env / "ktp_dummy.pdf"
    file_v1.write_bytes(b"DATA_KTP_ASLI_JAMAAH_01")

    # 2. Registrasi dokumen pertama kali (Harus v1)
    res1 = register_document(file_v1, "KTP_Jamaah", user_id=2)
    assert res1["status"] == "NEW_DOCUMENT"
    assert res1["version"] == 1

    # 3. Uji unggah file duplikat identik (Harus ditolak sebagai DUPLICATE)
    file_copy = isolated_env / "ktp_dummy_salinan.pdf"
    file_copy.write_bytes(b"DATA_KTP_ASLI_JAMAAH_01")
    res_dup = register_document(file_copy, "KTP_Jamaah", user_id=2)
    assert res_dup["status"] == "DUPLICATE"

    # 4. Uji unggah file revisi (Harus otomatis naik ke v2)
    file_v2 = isolated_env / "ktp_dummy_revisi.pdf"
    file_v2.write_bytes(b"DATA_KTP_REVISI_JAMAAH_01")
    res2 = register_document(file_v2, "KTP_Jamaah", user_id=2)
    assert res2["status"] == "NEW_VERSION"
    assert res2["version"] == 2

    # 5. Uji verifikasi keaslian (File asli = VALID, File diubah = MODIFIED)
    check_valid = verify_document_integrity(res1["doc_id"], file_v1, user_id=3)
    assert check_valid["is_valid"] is True
    assert check_valid["status"] == "VALID"

    check_modified = verify_document_integrity(res1["doc_id"], file_v2, user_id=3)
    assert check_modified["is_valid"] is False
    assert check_modified["status"] == "MODIFIED"

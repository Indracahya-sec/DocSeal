import pytest
from pathlib import Path
from src.database.seed import seed_database
from src.core.hasher import register_document, calculate_sha256
from src.core.crypto import encrypt_document, decrypt_document


@pytest.fixture
def crypto_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Menyiapkan environment database dan folder enkripsi terisolasi."""
    test_db = tmp_path / "test_docseal.db"
    test_enc_dir = tmp_path / "encrypted"
    test_enc_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("src.database.connection.DB_PATH", test_db)
    monkeypatch.setattr("src.core.crypto.ENCRYPTED_DIR", test_enc_dir)
    seed_database()
    return tmp_path


def test_aes256_encrypt_and_decrypt(crypto_env: Path):
    # 1. Siapkan dan daftarkan berkas dummy
    source_file = crypto_env / "paspor_dummy.pdf"
    original_content = b"RAHASIA_NEGARA_PASPOR_DUMMY_2026"
    source_file.write_bytes(original_content)

    reg = register_document(source_file, "Paspor_Jamaah", user_id=2)
    doc_id = reg["doc_id"]

    # 2. Enkripsi berkas dengan AES-256-GCM
    enc_res = encrypt_document(doc_id, passphrase="kunci_kuat_123", user_id=2)
    seal_path = Path(enc_res["encrypted_file"])
    assert seal_path.exists()
    assert seal_path.read_bytes() != original_content

    # 3. Dekripsi dengan passphrase SALAH wajib memunculkan ValueError
    decrypted_out = crypto_env / "hasil_dekripsi.pdf"
    with pytest.raises(ValueError, match="Dekripsi gagal"):
        decrypt_document(
            seal_path, "kunci_salah", decrypted_out, user_id=2, doc_id=doc_id
        )

    # 4. Dekripsi dengan passphrase BENAR wajib mengembalikan isi dan hash 100% identik
    decrypt_document(
        seal_path, "kunci_kuat_123", decrypted_out, user_id=2, doc_id=doc_id
    )
    assert decrypted_out.read_bytes() == original_content
    assert calculate_sha256(decrypted_out) == calculate_sha256(source_file)

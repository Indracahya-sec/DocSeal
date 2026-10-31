import os
from src.config import DB_PATH, DUMMY_DIR, ENCRYPTED_DIR, DATA_DIR
from src.database.seed import seed_database
from src.core.rbac import authenticate_user
from src.core.hasher import (
    register_document,
    verify_document_integrity,
    scan_all_documents_integrity,
)
from src.core.crypto import encrypt_document, decrypt_document
from src.core.audit import export_audit_logs_csv
from tests.generate_dummy import generate_all_dummies


def print_banner(title: str) -> None:
    print(f"\n{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}")


def run_interactive_demo() -> None:
    print_banner("SIMULASI OTOMATIS DOCSEAL - APPLIED CYBER SECURITY")

    # 1. Reset & Seed Database Bersih untuk Simulasi
    if DB_PATH.exists():
        os.remove(DB_PATH)
    seed_database()
    generate_all_dummies()

    # 2. Autentikasi Role
    print_banner("1. UJI AUTENTIKASI RBAC (OPERATOR, STAF, AUDITOR)")
    op = authenticate_user("operator", "operator123")
    staf = authenticate_user("staf", "staf123")
    auditor = authenticate_user("auditor", "auditor123")
    print(f"[+] Login Operator : {op['username']} (Role: {op['role']})")
    print(f"[+] Login Staf     : {staf['username']} (Role: {staf['role']})")
    print(f"[+] Login Auditor  : {auditor['username']} (Role: {auditor['role']})")

    # 3. Registrasi Dokumen, Deduplikasi, & Auto-Versioning
    print_banner("2. UJI SHA-256, DEDUPLIKASI, & AUTO-VERSIONING")
    f_v1 = DUMMY_DIR / "Berkas_Jamaah_01.pdf"
    f_copy = DUMMY_DIR / "Berkas_Jamaah_01_Copy.pdf"
    f_rev = DUMMY_DIR / "Berkas_Jamaah_01_Revisi.pdf"

    res_v1 = register_document(f_v1, "Berkas_Jamaah_01", op["user_id"])
    print(f"[1] Upload Asli   -> [{res_v1['status']}] {res_v1['message']}")
    print(f"    SHA-256       : {res_v1['sha256']}")

    res_dup = register_document(f_copy, "Berkas_Jamaah_01", op["user_id"])
    print(f"[2] Upload Salinan-> [{res_dup['status']}] {res_dup['message']}")

    res_v2 = register_document(f_rev, "Berkas_Jamaah_01", op["user_id"])
    print(f"[3] Upload Revisi -> [{res_v2['status']}] {res_v2['message']}")
    print(f"    SHA-256       : {res_v2['sha256']}")

    # 4. Verifikasi Integritas & Batch Scan
    print_banner("3. UJI VERIFIKASI INTEGRITAS & BATCH SCAN ARSIP")
    ver_ok = verify_document_integrity(res_v1["doc_id"], f_v1, staf["user_id"])
    print(f"[+] Verifikasi v1 vs File Asli   : {ver_ok['status']} (Cocok 100%)")

    ver_mod = verify_document_integrity(res_v1["doc_id"], f_rev, staf["user_id"])
    print(f"[!] Verifikasi v1 vs File Revisi : {ver_mod['status']} (Avalanche Effect Terdeteksi!)")

    scan_res = scan_all_documents_integrity(staf["user_id"])
    print(
        f"[+] Batch Scan Seluruh Arsip     : {scan_res['overall_status']} "
        f"(Total: {scan_res['total']}, Valid: {scan_res['valid_count']})"
    )

    # 5. Enkripsi & Dekripsi AES-256-GCM (.seal)
    print_banner("4. UJI ENKRIPSI & DEKRIPSI AES-256-GCM (.seal)")
    enc = encrypt_document(res_v1["doc_id"], "rahasiahaji2026", op["user_id"])
    print(f"[+] Enkripsi Berhasil : {enc['encrypted_file']}")

    dec_out = DUMMY_DIR / "Hasil_Dekripsi.pdf"
    dec = decrypt_document(
        enc["encrypted_file"],
        "rahasiahaji2026",
        dec_out,
        op["user_id"],
        doc_id=res_v1["doc_id"],
    )
    print(f"[+] Dekripsi Berhasil : {dec['output_file']}")

    # 6. Ekspor Audit Trail CSV oleh Auditor
    print_banner("5. EKSPOR LAPORAN AUDIT TRAIL (IMMUTABLE LOG)")
    csv_out = DATA_DIR / "DocSeal_Audit_Trail.csv"
    export_audit_logs_csv(auditor["user_id"], output_path=csv_out)
    print(f"[+] Laporan CSV Audit Trail tersimpan di: {csv_out}")
    print("\n[SELESAI] Seluruh skenario simulasi DocSeal berjalan sukses 100%!")


if __name__ == "__main__":
    run_interactive_demo()

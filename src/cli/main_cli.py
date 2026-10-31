import argparse
import sys
from src.database.connection import get_db_connection
from src.core.audit import log_action, export_audit_logs_csv
from src.core.rbac import authenticate_user, has_permission, create_user, list_users
from src.core.hasher import (
    register_document,
    verify_document_integrity,
    scan_all_documents_integrity,
)
from src.core.crypto import encrypt_document, decrypt_document


def require_auth_and_perm(username: str, password: str, action: str) -> dict:
    """Memvalidasi login sekaligus mengecek izin RBAC sebelum menjalankan perintah."""
    user = authenticate_user(username, password)
    if not user:
        print("[-] Autentikasi Gagal: Username atau password salah!")
        sys.exit(1)

    if not has_permission(user["role"], action):
        log_action(
            user_id=user["user_id"],
            action=action,
            status_result="ACCESS_DENIED",
            details=f"Role '{user['role']}' ditolak saat menjalankan aksi '{action}' via CLI",
        )
        print(
            f"[-] Akses Ditolak (RBAC): Role '{user['role']}' tidak diizinkan melakukan '{action}'."
        )
        sys.exit(1)

    return user


def cmd_list() -> None:
    """Menampilkan daftar dokumen yang terdaftar di database."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT d.doc_id, d.doc_name, d.version, d.sha256_hash, d.is_encrypted, u.username, d.created_at
        FROM documents d
        JOIN users u ON d.uploaded_by = u.user_id
        ORDER BY d.doc_id ASC
    """).fetchall()
    conn.close()

    if not rows:
        print("[=] Belum ada dokumen yang terdaftar di database.")
        return

    print("\n=== DAFTAR DOKUMEN DOCSEAL ===")
    for r in rows:
        enc_badge = "[ENCRYPTED]" if r["is_encrypted"] else "[PLAIN]"
        print(f"ID: {r['doc_id']} | {r['doc_name']} (v{r['version']}) {enc_badge}")
        print(f"    SHA-256 : {r['sha256_hash']}")
        print(f"    Uploader: {r['username']} pada {r['created_at']}\n")


def cmd_logs(username: str, password: str) -> None:
    """Menampilkan riwayat Audit Trail (Khusus Admin & Auditor)."""
    require_auth_and_perm(username, password, "VIEW_LOGS")
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT a.log_id, COALESCE(u.username, 'UNKNOWN') as actor, a.action,
               a.doc_id, a.status_result, a.details, a.timestamp
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.log_id DESC LIMIT 20
    """).fetchall()
    conn.close()

    print("\n=== RIWAYAT AUDIT TRAIL (20 TERBARU) ===")
    for r in rows:
        doc_info = f"DocID:{r['doc_id']}" if r["doc_id"] else "-"
        print(
            f"[{r['timestamp']}] #{r['log_id']} | User: {r['actor']} | Aksi: {r['action']} ({doc_info}) -> {r['status_result']}"
        )
        if r["details"]:
            print(f"    Detail: {r['details']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DocSeal CLI - Sistem Proteksi & Integritas Dokumen"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Sub-command: list
    subparsers.add_parser("list", help="Lihat daftar semua dokumen di database")

    # 2. Sub-command: upload
    up = subparsers.add_parser(
        "upload", help="Unggah dan daftarkan dokumen baru/revisi"
    )
    up.add_argument("-u", "--user", required=True, help="Username")
    up.add_argument("-p", "--password", required=True, help="Password")
    up.add_argument("-f", "--file", required=True, help="Path ke file dokumen")
    up.add_argument(
        "-n",
        "--name",
        required=True,
        help="Nama entitas dokumen (misal: Berkas_Jamaah_01)",
    )

    # 3. Sub-command: verify
    ver = subparsers.add_parser(
        "verify", help="Verifikasi keaslian file terhadap hash database"
    )
    ver.add_argument("-u", "--user", required=True, help="Username")
    ver.add_argument("-p", "--password", required=True, help="Password")
    ver.add_argument("-i", "--id", type=int, required=True, help="ID Dokumen (doc_id)")
    ver.add_argument(
        "-f", "--file", required=True, help="Path file fisik yang ingin diuji"
    )

    # 4. Sub-command: encrypt
    enc = subparsers.add_parser(
        "encrypt", help="Enkripsi dokumen menjadi file .seal (AES-256-GCM)"
    )
    enc.add_argument("-u", "--user", required=True, help="Username")
    enc.add_argument("-p", "--password", required=True, help="Password")
    enc.add_argument("-i", "--id", type=int, required=True, help="ID Dokumen (doc_id)")
    enc.add_argument(
        "-k", "--key", required=True, help="Passphrase kunci enkripsi AES-256"
    )

    # 5. Sub-command: decrypt
    dec = subparsers.add_parser(
        "decrypt", help="Dekripsi file .seal kembali ke PDF asli"
    )
    dec.add_argument("-u", "--user", required=True, help="Username")
    dec.add_argument("-p", "--password", required=True, help="Password")
    dec.add_argument("-f", "--file", required=True, help="Path ke file .seal")
    dec.add_argument(
        "-o", "--output", required=True, help="Path output file hasil dekripsi"
    )
    dec.add_argument(
        "-k", "--key", required=True, help="Passphrase kunci dekripsi AES-256"
    )
    dec.add_argument(
        "-i", "--id", type=int, default=None, help="ID Dokumen (opsional untuk Audit Log)"
    )

    # 6. Sub-command: logs
    lg = subparsers.add_parser("logs", help="Tampilkan catatan Audit Trail")
    lg.add_argument("-u", "--user", required=True, help="Username")
    lg.add_argument("-p", "--password", required=True, help="Password")

    # 7. Sub-command: add-user (Khusus Admin)
    au = subparsers.add_parser("add-user", help="Tambah pengguna baru (Khusus Admin)")
    au.add_argument("-u", "--user", required=True, help="Username Admin")
    au.add_argument("-p", "--password", required=True, help="Password Admin")
    au.add_argument("--new-user", required=True, help="Username akun baru")
    au.add_argument("--new-pass", required=True, help="Password akun baru")
    au.add_argument(
        "--role",
        required=True,
        choices=["admin", "operator", "staf", "auditor"],
        help="Role akun baru",
    )

    # 8. Sub-command: users (Khusus Admin)
    us = subparsers.add_parser("users", help="Lihat daftar pengguna (Khusus Admin)")
    us.add_argument("-u", "--user", required=True, help="Username Admin")
    us.add_argument("-p", "--password", required=True, help="Password Admin")

    # 9. Sub-command: scan (Batch Integrity Check seluruh dokumen di disk)
    sc = subparsers.add_parser(
        "scan", help="Pindai keutuhan seluruh arsip dokumen terdaftar (Batch Scan)"
    )
    sc.add_argument("-u", "--user", required=True, help="Username")
    sc.add_argument("-p", "--password", required=True, help="Password")

    # 10. Sub-command: export-logs (Ekspor Audit Trail ke CSV)
    el = subparsers.add_parser(
        "export-logs", help="Ekspor laporan Audit Trail ke file CSV (Khusus Admin/Auditor)"
    )
    el.add_argument("-u", "--user", required=True, help="Username")
    el.add_argument("-p", "--password", required=True, help="Password")
    el.add_argument(
        "-o",
        "--output",
        default="data/DocSeal_Audit_Trail.csv",
        help="Path file CSV output (default: data/DocSeal_Audit_Trail.csv)",
    )

    args = parser.parse_args()

    try:
        if args.command == "list":
            cmd_list()
        elif args.command == "upload":
            user = require_auth_and_perm(args.user, args.password, "UPLOAD")
            res = register_document(args.file, args.name, user["user_id"])
            print(f"[{res['status']}] {res['message']}\nSHA-256: {res['sha256']}")
        elif args.command == "verify":
            user = require_auth_and_perm(args.user, args.password, "VERIFY")
            res = verify_document_integrity(args.id, args.file, user["user_id"])
            print(f"\n=== HASIL VERIFIKASI INTEGRITAS ===")
            print(f"Dokumen       : {res['doc_name']} (v{res['version']})")
            print(f"Status        : {res['status']}")
            print(f"Hash Database : {res['expected_hash']}")
            print(f"Hash File Ini : {res['current_hash']}")
        elif args.command == "encrypt":
            user = require_auth_and_perm(args.user, args.password, "ENCRYPT")
            res = encrypt_document(args.id, args.key, user["user_id"])
            print(f"[+] {res['message']} -> {res['encrypted_file']}")
        elif args.command == "decrypt":
            user = require_auth_and_perm(args.user, args.password, "DECRYPT")
            res = decrypt_document(
                args.file, args.key, args.output, user["user_id"], doc_id=args.id
            )
            print(f"[+] {res['message']}")
        elif args.command == "logs":
            cmd_logs(args.user, args.password)
        elif args.command == "add-user":
            admin = require_auth_and_perm(args.user, args.password, "MANAGE_USERS")
            res = create_user(args.new_user, args.new_pass, args.role, admin["user_id"])
            print(f"[+] {res['message']} (ID: {res['user_id']})")
        elif args.command == "users":
            require_auth_and_perm(args.user, args.password, "MANAGE_USERS")
            print("\n=== DAFTAR AKUN PENGGUNA DOCSEAL ===")
            for u in list_users():
                print(
                    f"ID: {u['user_id']} | Username: {u['username']} | Role: {u['role'].upper()} | Dibuat: {u['created_at']}"
                )
        elif args.command == "scan":
            user = require_auth_and_perm(args.user, args.password, "VERIFY")
            res = scan_all_documents_integrity(user["user_id"])
            print(f"\n=== HASIL BATCH INTEGRITY SCAN ({res['overall_status']}) ===")
            print(
                f"Total: {res['total']} | Valid: {res['valid_count']} | Modified: {res['modified_count']} | Missing: {res['missing_count']}"
            )
            for item in res["results"]:
                print(
                    f"  - [ID:{item['doc_id']}] {item['doc_name']} (v{item['version']}) -> {item['status']}"
                )
        elif args.command == "export-logs":
            user = require_auth_and_perm(args.user, args.password, "VIEW_LOGS")
            export_audit_logs_csv(user["user_id"], output_path=args.output)
            print(f"[+] Laporan Audit Trail berhasil diekspor ke: {args.output}")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

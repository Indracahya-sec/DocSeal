import argparse
from collections.abc import Callable
import sys
from typing import Any

from src.database.connection import db_session
from src.core.audit import export_audit_logs_csv, log_action
from src.core.crypto import decrypt_document, encrypt_document
from src.core.hasher import (
    register_document,
    scan_all_documents_integrity,
    verify_document_integrity,
)
from src.core.rbac import ROLE_PERMISSIONS, authenticate_user, create_user, has_permission, list_users
from tests.generate_dummy import create_custom_pdf, interactive_prompt


def require_auth_and_perm(username: str, password: str, action: str) -> dict[str, Any]:
    """Memvalidasi login sekaligus mengecek izin RBAC sebelum menjalankan perintah."""
    if not (user := authenticate_user(username, password)):
        print("[-] Autentikasi Gagal: Username atau password salah!")
        sys.exit(1)

    if not has_permission(user["role"], action):
        log_action(
            user["user_id"],
            action,
            "ACCESS_DENIED",
            details=f"Role '{user['role']}' ditolak saat menjalankan aksi '{action}' via CLI",
        )
        print(f"[-] Akses Ditolak (RBAC): Role '{user['role']}' tidak diizinkan melakukan '{action}'.")
        sys.exit(1)

    return user


def cmd_list() -> None:
    """Menampilkan daftar dokumen yang terdaftar di database."""
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT d.doc_id, d.doc_name, d.version, d.sha256_hash, d.is_encrypted, u.username, d.created_at
            FROM documents d
            JOIN users u ON d.uploaded_by = u.user_id
            ORDER BY d.doc_id ASC
            """
        ).fetchall()

    if not rows:
        print("[=] Belum ada dokumen yang terdaftar di database.")
        return

    print("\n=== DAFTAR DOKUMEN DOCSEAL ===")
    for r in rows:
        badge = "[ENCRYPTED]" if r["is_encrypted"] else "[PLAIN]"
        print(
            f"ID: {r['doc_id']} | {r['doc_name']} (v{r['version']}) {badge}\n"
            f"    SHA-256 : {r['sha256_hash']}\n"
            f"    Uploader: {r['username']} pada {r['created_at']}\n"
        )


def cmd_logs(username: str, password: str) -> None:
    """Menampilkan riwayat Audit Trail (Khusus Admin & Auditor)."""
    require_auth_and_perm(username, password, "VIEW_LOGS")
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT a.log_id, COALESCE(u.username, 'UNKNOWN') AS actor, a.action,
                   a.doc_id, a.status_result, a.details, a.timestamp
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            ORDER BY a.log_id DESC LIMIT 20
            """
        ).fetchall()

    print("\n=== RIWAYAT AUDIT TRAIL (20 TERBARU) ===")
    for r in rows:
        doc_info = f"DocID:{r['doc_id']}" if r["doc_id"] else "-"
        print(f"[{r['timestamp']}] #{r['log_id']} | User: {r['actor']} | Aksi: {r['action']} ({doc_info}) -> {r['status_result']}")
        if r["details"]:
            print(f"    Detail: {r['details']}")


def _build_parser() -> argparse.ArgumentParser:
    """Menyusun definisi sub-command CLI DocSeal secara deklaratif."""
    parser = argparse.ArgumentParser(description="DocSeal CLI - Sistem Proteksi & Integritas Dokumen")
    subs = parser.add_subparsers(dest="command", required=True)

    def auth_sub(name: str, help_text: str) -> argparse.ArgumentParser:
        sub = subs.add_parser(name, help=help_text)
        sub.add_argument("-u", "--user", required=True, help="Username")
        sub.add_argument("-p", "--password", required=True, help="Password")
        return sub

    subs.add_parser("list", help="Lihat daftar semua dokumen di database")

    up = auth_sub("upload", "Unggah dan daftarkan dokumen baru/revisi")
    up.add_argument("-f", "--file", required=True, help="Path ke file dokumen")
    up.add_argument("-n", "--name", required=True, help="Nama entitas dokumen")

    ver = auth_sub("verify", "Verifikasi keaslian file terhadap hash database")
    ver.add_argument("-i", "--id", type=int, required=True, help="ID Dokumen (doc_id)")
    ver.add_argument("-f", "--file", required=True, help="Path file fisik yang ingin diuji")

    enc = auth_sub("encrypt", "Enkripsi dokumen menjadi file .seal (AES-256-GCM)")
    enc.add_argument("-i", "--id", type=int, required=True, help="ID Dokumen (doc_id)")
    enc.add_argument("-k", "--key", required=True, help="Passphrase kunci enkripsi AES-256")

    dec = auth_sub("decrypt", "Dekripsi file .seal kembali ke PDF asli")
    dec.add_argument("-f", "--file", required=True, help="Path ke file .seal")
    dec.add_argument("-o", "--output", required=True, help="Path output file hasil dekripsi")
    dec.add_argument("-k", "--key", required=True, help="Passphrase kunci dekripsi AES-256")
    dec.add_argument("-i", "--id", type=int, default=None, help="ID Dokumen (opsional untuk Audit Log)")

    auth_sub("logs", "Tampilkan catatan Audit Trail")

    au = auth_sub("add-user", "Tambah pengguna baru (Khusus Admin)")
    au.add_argument("--new-user", required=True, help="Username akun baru")
    au.add_argument("--new-pass", required=True, help="Password akun baru")
    au.add_argument("--role", required=True, choices=tuple(ROLE_PERMISSIONS), help="Role akun baru")

    auth_sub("users", "Lihat daftar pengguna (Khusus Admin)")
    auth_sub("scan", "Pindai keutuhan seluruh arsip dokumen terdaftar (Batch Scan)")

    el = auth_sub("export-logs", "Ekspor laporan Audit Trail ke file CSV (Khusus Admin/Auditor)")
    el.add_argument("-o", "--output", default="data/DocSeal_Audit_Trail.csv", help="Path file CSV output")

    md = subs.add_parser("make-dummy", help="Buat file PDF dummy dengan nama dan isi kustom")
    md.add_argument("-n", "--name", help="Nama file dokumen")
    md.add_argument("-i", "--isi", dest="content", help="Isi teks di dalam PDF")

    return parser


def _handle_upload(args: argparse.Namespace) -> None:
    user = require_auth_and_perm(args.user, args.password, "UPLOAD")
    res = register_document(args.file, args.name, user["user_id"])
    print(f"[{res['status']}] {res['message']}\nSHA-256: {res['sha256']}")


def _handle_verify(args: argparse.Namespace) -> None:
    user = require_auth_and_perm(args.user, args.password, "VERIFY")
    res = verify_document_integrity(args.id, args.file, user["user_id"])
    print(
        f"\n=== HASIL VERIFIKASI INTEGRITAS ===\n"
        f"Dokumen       : {res['doc_name']} (v{res['version']})\n"
        f"Status        : {res['status']}\n"
        f"Hash Database : {res['expected_hash']}\n"
        f"Hash File Ini : {res['current_hash']}"
    )


def _handle_encrypt(args: argparse.Namespace) -> None:
    user = require_auth_and_perm(args.user, args.password, "ENCRYPT")
    res = encrypt_document(args.id, args.key, user["user_id"])
    print(f"[+] {res['message']} -> {res['encrypted_file']}")


def _handle_decrypt(args: argparse.Namespace) -> None:
    user = require_auth_and_perm(args.user, args.password, "DECRYPT")
    res = decrypt_document(args.file, args.key, args.output, user["user_id"], doc_id=args.id)
    print(f"[+] {res['message']}")


def _handle_add_user(args: argparse.Namespace) -> None:
    admin = require_auth_and_perm(args.user, args.password, "MANAGE_USERS")
    res = create_user(args.new_user, args.new_pass, args.role, admin["user_id"])
    print(f"[+] {res['message']} (ID: {res['user_id']})")


def _handle_users(args: argparse.Namespace) -> None:
    require_auth_and_perm(args.user, args.password, "MANAGE_USERS")
    print("\n=== DAFTAR AKUN PENGGUNA DOCSEAL ===")
    for u in list_users():
        print(f"ID: {u['user_id']} | Username: {u['username']} | Role: {u['role'].upper()} | Dibuat: {u['created_at']}")


def _handle_scan(args: argparse.Namespace) -> None:
    user = require_auth_and_perm(args.user, args.password, "VERIFY")
    res = scan_all_documents_integrity(user["user_id"])
    print(
        f"\n=== HASIL BATCH INTEGRITY SCAN ({res['overall_status']}) ===\n"
        f"Total: {res['total']} | Valid: {res['valid_count']} | Modified: {res['modified_count']} | Missing: {res['missing_count']}"
    )
    for item in res["results"]:
        print(f"  - [ID:{item['doc_id']}] {item['doc_name']} (v{item['version']}) -> {item['status']}")


def _handle_export_logs(args: argparse.Namespace) -> None:
    user = require_auth_and_perm(args.user, args.password, "VIEW_LOGS")
    export_audit_logs_csv(user["user_id"], output_path=args.output)
    print(f"[+] Laporan Audit Trail berhasil diekspor ke: {args.output}")


def main() -> None:
    args = _build_parser().parse_args()
    handlers: dict[str, Callable[[argparse.Namespace], None]] = {
        "list": lambda _: cmd_list(),
        "upload": _handle_upload,
        "verify": _handle_verify,
        "encrypt": _handle_encrypt,
        "decrypt": _handle_decrypt,
        "logs": lambda a: cmd_logs(a.user, a.password),
        "add-user": _handle_add_user,
        "users": _handle_users,
        "scan": _handle_scan,
        "export-logs": _handle_export_logs,
        "make-dummy": lambda a: create_custom_pdf(a.name, a.content) if (a.name and a.content) else interactive_prompt(),
    }

    try:
        handlers[args.command](args)
    except Exception as exc:
        print(f"[-] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

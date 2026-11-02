from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
from typing import Any

from flask import Flask, Response, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from src.config import DATA_DIR, DUMMY_DIR, ENCRYPTED_DIR, SECRET_KEY, ensure_directories
from src.core.audit import export_audit_logs_csv, log_action
from src.core.crypto import decrypt_document, encrypt_document
from src.core.hasher import register_document, scan_all_documents_integrity, verify_document_integrity
from src.core.rbac import authenticate_user, create_user, has_permission, is_account_locked, list_users
from src.database.connection import db_session
from tests.generate_dummy import create_custom_pdf

app = Flask(__name__)
app.secret_key = SECRET_KEY


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator untuk memastikan pengguna sudah login."""
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return f(*args, **kwargs) if "user_id" in session else redirect(url_for("login"))
    return wrapper


def require_perm(*perms: str, action: str, denied_msg: str) -> Callable[..., Any]:
    """Decorator gabungan autentikasi sesi, pemeriksaan RBAC, dan pencatatan ACCESS_DENIED."""
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        @login_required
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not any(has_permission(session["role"], p) for p in perms):
                log_action(
                    session["user_id"],
                    action,
                    "ACCESS_DENIED",
                    doc_id=kwargs.get("doc_id"),
                    details=f"Role '{session['role']}' mencoba aksi '{action}' tanpa izin",
                )
                flash(f"Akses Ditolak: {denied_msg}", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


@contextmanager
def _saved_temp_upload(file_storage: FileStorage, prefix: str) -> Iterator[Path]:
    """Menyimpan file unggahan sementara dan menghapusnya otomatis setelah selesai diproses."""
    ensure_directories()
    temp_path = DATA_DIR / f"{prefix}_{os.getpid()}_{secure_filename(file_storage.filename or 'file')}"
    file_storage.save(temp_path)
    try:
        yield temp_path
    finally:
        temp_path.unlink(missing_ok=True)


def get_dashboard_data(role: str) -> tuple[list[Any], list[Any], list[dict[str, Any]]]:
    """Mengambil daftar dokumen, audit log, dan daftar pengguna sesuai hak akses role."""
    with db_session() as conn:
        docs = conn.execute(
            """
            SELECT d.*, u.username AS uploader
            FROM documents d
            JOIN users u ON d.uploaded_by = u.user_id
            ORDER BY d.doc_id DESC
            """
        ).fetchall()
        logs = (
            conn.execute(
                """
                SELECT a.*, COALESCE(u.username, 'UNKNOWN') AS actor
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.user_id
                ORDER BY a.log_id DESC LIMIT 30
                """
            ).fetchall()
            if has_permission(role, "VIEW_LOGS")
            else []
        )
    users = list_users() if has_permission(role, "MANAGE_USERS") else []
    return docs, logs, users


def _render_dashboard(**extra: Any) -> str:
    docs, logs, users = get_dashboard_data(session["role"])
    return render_template(
        "dashboard.html",
        docs=docs,
        logs=logs,
        users=users,
        verify_result=extra.get("verify_result"),
        scan_result=extra.get("scan_result"),
    )


def _resolve_encrypted_seal(doc_id: int, unencrypted_msg: str) -> tuple[Any, Path] | None:
    """Mengambil metadata dokumen terenkripsi beserta lokasi fisik file .seal."""
    with db_session() as conn:
        doc = conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()

    if not doc or not doc["is_encrypted"]:
        flash(unencrypted_msg, "warning")
        return None

    seal_path = ENCRYPTED_DIR / f"{Path(doc['file_path']).stem}_v{doc['version']}.seal"
    if not seal_path.exists():
        flash("File fisik .seal tidak ditemukan di server lokal.", "danger")
        return None

    return doc, seal_path


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if user := authenticate_user(username, password):
            session.update(user_id=user["user_id"], username=user["username"], role=user["role"])
            flash(f"Selamat datang, {user['username']} (Role: {user['role'].upper()})", "success")
            return redirect(url_for("dashboard"))

        msg, category = (
            ("Akun dikunci sementara (Brute-Force Protection): Terlalu banyak percobaan login gagal beruntun!", "warning")
            if is_account_locked(username)
            else ("Login gagal! Username atau password salah.", "danger")
        )
        flash(msg, category)
    return render_template("login.html")


@app.route("/logout")
def logout() -> Any:
    if uid := session.get("user_id"):
        log_action(uid, "LOGOUT", "SUCCESS", details=f"User '{session.get('username')}' keluar dari sesi Web UI")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard() -> str:
    return _render_dashboard()


@app.route("/generate-dummy", methods=["POST"])
@require_perm("UPLOAD", action="GENERATE_DUMMY", denied_msg="Role Anda tidak memiliki izin membuat dokumen dummy.")
def generate_dummy_route() -> Any:
    doc_name = request.form.get("doc_name", "").strip()
    content = request.form.get("content", "").strip()
    mode = request.form.get("mode", "save_only")

    if not (doc_name and content):
        flash("Nama dokumen dan isi teks dokumen wajib diisi!", "warning")
        return redirect(url_for("dashboard"))

    pdf_path = create_custom_pdf(filename=doc_name, content=content, output_dir=DUMMY_DIR)
    log_action(session["user_id"], "GENERATE_DUMMY", "SUCCESS", details=f"Membuat berkas PDF dummy kustom: {pdf_path.name}")

    if mode == "download":
        return send_file(pdf_path, as_attachment=True, download_name=pdf_path.name)

    if mode == "register":
        entity = Path(doc_name).stem.strip().replace(" ", "_") or "Dokumen_Dummy"
        res = register_document(pdf_path, entity, session["user_id"])
        if res["status"] == "DUPLICATE":
            flash(f"[DUPLIKAT DITOLAK] {res['message']}", "danger")
        else:
            flash(f"[DUMMY + {res['status']}] PDF '{pdf_path.name}' berhasil dibuat & terdaftar sebagai {entity} (v{res['version']})", "success")
        return redirect(url_for("dashboard"))

    flash(f"[PDF DUMMY DIBUAT] Tersimpan di data/dummy_docs/{pdf_path.name}", "success")
    return redirect(url_for("dashboard"))


@app.route("/upload", methods=["POST"])
@require_perm("UPLOAD", action="UPLOAD", denied_msg="Role Anda tidak memiliki izin unggah dokumen.")
def upload() -> Any:
    doc_name = request.form.get("doc_name", "").strip()
    uploaded = request.files.get("file")

    if not (doc_name and uploaded and uploaded.filename):
        flash("Nama dokumen dan berkas wajib diisi!", "warning")
        return redirect(url_for("dashboard"))

    with _saved_temp_upload(uploaded, "temp_upload") as temp_upload:
        res = register_document(temp_upload, doc_name, session["user_id"])
        if res["status"] == "DUPLICATE":
            flash(f"[DUPLIKAT DITOLAK] {res['message']}", "danger")
        else:
            ext = Path(secure_filename(uploaded.filename)).suffix or ".pdf"
            final_path = DUMMY_DIR / f"{secure_filename(doc_name) or 'Dokumen'}_v{res['version']}{ext}"
            temp_upload.replace(final_path)
            with db_session() as conn:
                conn.execute("UPDATE documents SET file_path = ? WHERE doc_id = ?", (str(final_path), res["doc_id"]))
            flash(f"[{res['status']}] {res['message']} | SHA-256: {res['sha256'][:16]}...", "success")

    return redirect(url_for("dashboard"))


@app.route("/verify", methods=["POST"])
@require_perm("VERIFY", action="VERIFY", denied_msg="Role Anda tidak diizinkan memverifikasi dokumen.")
def verify() -> Any:
    doc_id = request.form.get("doc_id", type=int)
    test_file = request.files.get("file")

    if not (doc_id and test_file and test_file.filename):
        flash("Pilih dokumen acuan dan unggah berkas yang ingin diuji!", "warning")
        return redirect(url_for("dashboard"))

    with _saved_temp_upload(test_file, "temp_verify") as temp_path:
        verify_res = verify_document_integrity(doc_id, temp_path, session["user_id"])

    return _render_dashboard(verify_result=verify_res)


@app.route("/scan", methods=["POST"])
@require_perm("VERIFY", action="BATCH_SCAN", denied_msg="Role Anda tidak diizinkan memindai dokumen.")
def scan_all_route() -> str:
    return _render_dashboard(scan_result=scan_all_documents_integrity(session["user_id"]))


@app.route("/logs/export-csv")
@require_perm("VIEW_LOGS", action="EXPORT_LOGS", denied_msg="Hanya Admin dan Auditor yang dapat mengekspor laporan Audit Trail.")
def export_logs_route() -> Response:
    return Response(
        export_audit_logs_csv(session["user_id"]),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=DocSeal_Audit_Trail.csv"},
    )


@app.route("/encrypt", methods=["POST"])
@require_perm("ENCRYPT", action="ENCRYPT", denied_msg="Role Anda tidak diizinkan mengenkripsi dokumen.")
def encrypt_route() -> Any:
    doc_id = request.form.get("doc_id", type=int)
    passphrase = request.form.get("passphrase", "")

    if not doc_id or len(passphrase) < 4:
        flash("Masukkan passphrase minimal 4 karakter untuk enkripsi AES-256!", "warning")
        return redirect(url_for("dashboard"))

    try:
        res = encrypt_document(doc_id, passphrase, session["user_id"])
        flash(f"[AES-256-GCM] {res['message']}", "success")
    except (ValueError, FileNotFoundError) as exc:
        flash(f"Gagal enkripsi: {exc}", "danger")

    return redirect(url_for("dashboard"))


@app.route("/decrypt", methods=["POST"])
@require_perm("DECRYPT", action="DECRYPT", denied_msg="Role Anda tidak diizinkan mendekripsi dokumen.")
def decrypt_route() -> Any:
    doc_id = request.form.get("doc_id", type=int)
    passphrase = request.form.get("passphrase", "")

    if not (doc_id and passphrase):
        flash("Pilih dokumen terenkripsi dan masukkan passphrase dekripsi!", "warning")
        return redirect(url_for("dashboard"))

    if not (resolved := _resolve_encrypted_seal(doc_id, "Dokumen belum dienkripsi ke format .seal.")):
        return redirect(url_for("dashboard"))

    doc, seal_path = resolved
    ext = Path(doc["file_path"]).suffix or ".pdf"
    decrypted_filename = f"Decrypted_{doc['doc_name']}_v{doc['version']}{ext}"
    output_path = DUMMY_DIR / decrypted_filename

    try:
        decrypt_document(seal_path, passphrase, output_path, session["user_id"], doc_id=doc_id)
        return send_file(output_path, as_attachment=True, download_name=decrypted_filename)
    except (ValueError, FileNotFoundError) as exc:
        flash(f"[AES-256-GCM] {exc}", "danger")
        return redirect(url_for("dashboard"))


@app.route("/users/create", methods=["POST"])
@require_perm("MANAGE_USERS", action="MANAGE_USERS", denied_msg="Hanya Admin yang dapat mengelola pengguna.")
def create_user_route() -> Any:
    try:
        res = create_user(
            request.form.get("username", ""),
            request.form.get("password", ""),
            request.form.get("role", ""),
            session["user_id"],
        )
        flash(f"[RBAC] {res['message']}", "success")
    except ValueError as exc:
        flash(f"Gagal membuat pengguna: {exc}", "danger")

    return redirect(url_for("dashboard"))


@app.route("/download-seal/<int:doc_id>")
@require_perm("ENCRYPT", "DECRYPT", action="DOWNLOAD_SEAL", denied_msg="Role Anda tidak memiliki izin mengunduh arsip terenkripsi (.seal).")
def download_seal(doc_id: int) -> Any:
    if not (resolved := _resolve_encrypted_seal(doc_id, "File terenkripsi (.seal) belum tersedia untuk dokumen ini.")):
        return redirect(url_for("dashboard"))

    _, seal_path = resolved
    log_action(session["user_id"], "DOWNLOAD_SEAL", "SUCCESS", doc_id=doc_id, details=f"Mengunduh arsip terenkripsi {seal_path.name}")
    return send_file(seal_path, as_attachment=True)

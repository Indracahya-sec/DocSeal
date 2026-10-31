import os
from pathlib import Path
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, Response
)
from werkzeug.utils import secure_filename

from src.config import SECRET_KEY, DUMMY_DIR, ENCRYPTED_DIR, DATA_DIR, ensure_directories
from src.database.connection import get_db_connection
from src.core.audit import log_action, export_audit_logs_csv
from src.core.rbac import authenticate_user, has_permission, list_users, create_user, is_account_locked
from src.core.hasher import register_document, verify_document_integrity, scan_all_documents_integrity
from src.core.crypto import encrypt_document, decrypt_document

app = Flask(__name__)
app.secret_key = SECRET_KEY

def login_required(f):
    """Decorator untuk memastikan pengguna sudah login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def get_dashboard_data(role: str) -> tuple:
    """Mengambil daftar dokumen, audit log, dan daftar pengguna sesuai hak akses role."""
    conn = get_db_connection()
    docs = conn.execute("""
        SELECT d.*, u.username as uploader
        FROM documents d
        JOIN users u ON d.uploaded_by = u.user_id
        ORDER BY d.doc_id DESC
    """).fetchall()

    logs = []
    if has_permission(role, "VIEW_LOGS"):
        logs = conn.execute("""
            SELECT a.*, COALESCE(u.username, 'UNKNOWN') as actor
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            ORDER BY a.log_id DESC LIMIT 30
        """).fetchall()
    conn.close()

    users = list_users() if has_permission(role, "MANAGE_USERS") else []
    return docs, logs, users

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = authenticate_user(username, password)
        if user:
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Selamat datang, {user['username']} (Role: {user['role'].upper()})", "success")
            return redirect(url_for("dashboard"))
        if is_account_locked(username):
            flash("Akun dikunci sementara (Brute-Force Protection): Terlalu banyak percobaan login gagal beruntun!", "warning")
        else:
            flash("Login gagal! Username atau password salah.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(
            user_id=session["user_id"],
            action="LOGOUT",
            status_result="SUCCESS",
            details=f"User '{session.get('username')}' keluar dari sesi Web UI",
        )
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    docs, logs, users = get_dashboard_data(session["role"])
    return render_template("dashboard.html", docs=docs, logs=logs, users=users, verify_result=None, scan_result=None)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if not has_permission(session["role"], "UPLOAD"):
        log_action(
            user_id=session["user_id"],
            action="UPLOAD",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba unggah dokumen tanpa izin",
        )
        flash("Akses Ditolak: Role Anda tidak memiliki izin unggah dokumen.", "danger")
        return redirect(url_for("dashboard"))

    doc_name = request.form.get("doc_name", "").strip()
    uploaded_file = request.files.get("file")

    if not doc_name or not uploaded_file or uploaded_file.filename == "":
        flash("Nama dokumen dan berkas wajib diisi!", "warning")
        return redirect(url_for("dashboard"))

    ensure_directories()
    safe_name = secure_filename(uploaded_file.filename)
    temp_upload = DATA_DIR / f"temp_upload_{os.getpid()}_{safe_name}"
    uploaded_file.save(temp_upload)

    try:
        res = register_document(temp_upload, doc_name, session["user_id"])
        if res["status"] == "DUPLICATE":
            flash(f"[DUPLIKAT DITOLAK] {res['message']}", "danger")
        else:
            ext = Path(safe_name).suffix or ".pdf"
            safe_doc_stem = secure_filename(doc_name) or "Dokumen"
            final_name = f"{safe_doc_stem}_v{res['version']}{ext}"
            final_path = DUMMY_DIR / final_name
            temp_upload.replace(final_path)

            conn = get_db_connection()
            conn.execute(
                "UPDATE documents SET file_path = ? WHERE doc_id = ?",
                (str(final_path), res["doc_id"]),
            )
            conn.commit()
            conn.close()
            flash(f"[{res['status']}] {res['message']} | SHA-256: {res['sha256'][:16]}...", "success")
    finally:
        if temp_upload.exists():
            os.remove(temp_upload)

    return redirect(url_for("dashboard"))

@app.route("/verify", methods=["POST"])
@login_required
def verify():
    if not has_permission(session["role"], "VERIFY"):
        log_action(
            user_id=session["user_id"],
            action="VERIFY",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba verifikasi tanpa izin",
        )
        flash("Akses Ditolak: Role Anda tidak diizinkan memverifikasi dokumen.", "danger")
        return redirect(url_for("dashboard"))

    doc_id = request.form.get("doc_id", type=int)
    test_file = request.files.get("file")

    if not doc_id or not test_file or test_file.filename == "":
        flash("Pilih dokumen acuan dan unggah berkas yang ingin diuji!", "warning")
        return redirect(url_for("dashboard"))

    ensure_directories()
    temp_path = DATA_DIR / f"temp_verify_{os.getpid()}_{secure_filename(test_file.filename)}"
    test_file.save(temp_path)

    try:
        verify_res = verify_document_integrity(doc_id, temp_path, session["user_id"])
    finally:
        if temp_path.exists():
            os.remove(temp_path)

    docs, logs, users = get_dashboard_data(session["role"])
    return render_template("dashboard.html", docs=docs, logs=logs, users=users, verify_result=verify_res, scan_result=None)

@app.route("/scan", methods=["POST"])
@login_required
def scan_all_route():
    if not has_permission(session["role"], "VERIFY"):
        log_action(
            user_id=session["user_id"],
            action="BATCH_SCAN",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba melakukan Batch Scan tanpa izin",
        )
        flash("Akses Ditolak: Role Anda tidak diizinkan memindai dokumen.", "danger")
        return redirect(url_for("dashboard"))

    scan_res = scan_all_documents_integrity(session["user_id"])
    docs, logs, users = get_dashboard_data(session["role"])
    return render_template("dashboard.html", docs=docs, logs=logs, users=users, verify_result=None, scan_result=scan_res)

@app.route("/logs/export-csv")
@login_required
def export_logs_route():
    if not has_permission(session["role"], "VIEW_LOGS"):
        log_action(
            user_id=session["user_id"],
            action="EXPORT_LOGS",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba mengekspor Audit Log tanpa izin",
        )
        flash("Akses Ditolak: Hanya Admin dan Auditor yang dapat mengekspor laporan Audit Trail.", "danger")
        return redirect(url_for("dashboard"))

    csv_data = export_audit_logs_csv(session["user_id"])
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=DocSeal_Audit_Trail.csv"},
    )

@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt_route():
    if not has_permission(session["role"], "ENCRYPT"):
        log_action(
            user_id=session["user_id"],
            action="ENCRYPT",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba enkripsi tanpa izin",
        )
        flash("Akses Ditolak: Role Anda tidak diizinkan mengenkripsi dokumen.", "danger")
        return redirect(url_for("dashboard"))

    doc_id = request.form.get("doc_id", type=int)
    passphrase = request.form.get("passphrase", "")

    if not doc_id or len(passphrase) < 4:
        flash("Masukkan passphrase minimal 4 karakter untuk enkripsi AES-256!", "warning")
        return redirect(url_for("dashboard"))

    try:
        res = encrypt_document(doc_id, passphrase, session["user_id"])
        flash(f"[AES-256-GCM] {res['message']}", "success")
    except Exception as e:
        flash(f"Gagal enkripsi: {e}", "danger")

    return redirect(url_for("dashboard"))

@app.route("/decrypt", methods=["POST"])
@login_required
def decrypt_route():
    if not has_permission(session["role"], "DECRYPT"):
        log_action(
            user_id=session["user_id"],
            action="DECRYPT",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba dekripsi tanpa izin",
        )
        flash("Akses Ditolak: Role Anda tidak diizinkan mendekripsi dokumen.", "danger")
        return redirect(url_for("dashboard"))

    doc_id = request.form.get("doc_id", type=int)
    passphrase = request.form.get("passphrase", "")

    if not doc_id or not passphrase:
        flash("Pilih dokumen terenkripsi dan masukkan passphrase dekripsi!", "warning")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    doc = conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()
    conn.close()

    if not doc or not doc["is_encrypted"]:
        flash("Dokumen belum dienkripsi ke format .seal.", "warning")
        return redirect(url_for("dashboard"))

    source_path = Path(doc["file_path"])
    seal_path = ENCRYPTED_DIR / f"{source_path.stem}_v{doc['version']}.seal"
    if not seal_path.exists():
        flash("File fisik .seal tidak ditemukan di server lokal.", "danger")
        return redirect(url_for("dashboard"))

    ext = source_path.suffix or ".pdf"
    decrypted_filename = f"Decrypted_{doc['doc_name']}_v{doc['version']}{ext}"
    output_path = DUMMY_DIR / decrypted_filename

    try:
        decrypt_document(
            encrypted_path=seal_path,
            passphrase=passphrase,
            output_path=output_path,
            user_id=session["user_id"],
            doc_id=doc_id,
        )
        return send_file(output_path, as_attachment=True, download_name=decrypted_filename)
    except Exception as e:
        flash(f"[AES-256-GCM] {e}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/users/create", methods=["POST"])
@login_required
def create_user_route():
    if not has_permission(session["role"], "MANAGE_USERS"):
        log_action(
            user_id=session["user_id"],
            action="MANAGE_USERS",
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba membuat user baru tanpa izin",
        )
        flash("Akses Ditolak: Hanya Admin yang dapat mengelola pengguna.", "danger")
        return redirect(url_for("dashboard"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()

    try:
        res = create_user(username, password, role, session["user_id"])
        flash(f"[RBAC] {res['message']}", "success")
    except Exception as e:
        flash(f"Gagal membuat pengguna: {e}", "danger")

    return redirect(url_for("dashboard"))

@app.route("/download-seal/<int:doc_id>")
@login_required
def download_seal(doc_id: int):
    if not (has_permission(session["role"], "ENCRYPT") or has_permission(session["role"], "DECRYPT")):
        log_action(
            user_id=session["user_id"],
            action="DOWNLOAD_SEAL",
            doc_id=doc_id,
            status_result="ACCESS_DENIED",
            details=f"Role '{session['role']}' mencoba mengunduh file .seal tanpa izin",
        )
        flash("Akses Ditolak: Role Anda tidak memiliki izin mengunduh arsip terenkripsi (.seal).", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    doc = conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()
    conn.close()

    if not doc or not doc["is_encrypted"]:
        flash("File terenkripsi (.seal) belum tersedia untuk dokumen ini.", "warning")
        return redirect(url_for("dashboard"))

    source_stem = Path(doc["file_path"]).stem
    seal_path = ENCRYPTED_DIR / f"{source_stem}_v{doc['version']}.seal"
    if not seal_path.exists():
        flash("File fisik .seal tidak ditemukan di server lokal.", "danger")
        return redirect(url_for("dashboard"))

    log_action(
        user_id=session["user_id"],
        action="DOWNLOAD_SEAL",
        doc_id=doc_id,
        status_result="SUCCESS",
        details=f"Mengunduh arsip terenkripsi {seal_path.name}",
    )
    return send_file(seal_path, as_attachment=True)

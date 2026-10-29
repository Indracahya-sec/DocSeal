import os
from pathlib import Path
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file
)
from werkzeug.utils import secure_filename

from src.config import SECRET_KEY, DUMMY_DIR, ENCRYPTED_DIR, DATA_DIR, ensure_directories
from src.database.connection import get_db_connection
from src.core.rbac import authenticate_user, has_permission
from src.core.hasher import register_document, verify_document_integrity
from src.core.crypto import encrypt_document

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
    """Mengambil daftar dokumen dan audit log sesuai hak akses role."""
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
    return docs, logs

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
        flash("Login gagal! Username atau password salah.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    docs, logs = get_dashboard_data(session["role"])
    return render_template("dashboard.html", docs=docs, logs=logs, verify_result=None)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if not has_permission(session["role"], "UPLOAD"):
        flash("Akses Ditolak: Role Anda tidak memiliki izin unggah dokumen.", "danger")
        return redirect(url_for("dashboard"))

    doc_name = request.form.get("doc_name", "").strip()
    uploaded_file = request.files.get("file")

    if not doc_name or not uploaded_file or uploaded_file.filename == "":
        flash("Nama dokumen dan berkas wajib diisi!", "warning")
        return redirect(url_for("dashboard"))

    ensure_directories()
    safe_name = secure_filename(uploaded_file.filename)
    save_path = DUMMY_DIR / safe_name
    uploaded_file.save(save_path)

    res = register_document(save_path, doc_name, session["user_id"])
    if res["status"] == "DUPLICATE":
        flash(f"[DUPLIKAT DITOLAK] {res['message']}", "danger")
    else:
        flash(f"[{res['status']}] {res['message']} | SHA-256: {res['sha256'][:16]}...", "success")

    return redirect(url_for("dashboard"))

@app.route("/verify", methods=["POST"])
@login_required
def verify():
    if not has_permission(session["role"], "VERIFY"):
        flash("Akses Ditolak: Role Anda tidak diizinkan memverifikasi dokumen.", "danger")
        return redirect(url_for("dashboard"))

    doc_id = request.form.get("doc_id", type=int)
    test_file = request.files.get("file")

    if not doc_id or not test_file or test_file.filename == "":
        flash("Pilih dokumen acuan dan unggah berkas yang ingin diuji!", "warning")
        return redirect(url_for("dashboard"))

    ensure_directories()
    temp_path = DATA_DIR / f"temp_verify_{secure_filename(test_file.filename)}"
    test_file.save(temp_path)

    try:
        verify_res = verify_document_integrity(doc_id, temp_path, session["user_id"])
    finally:
        if temp_path.exists():
            os.remove(temp_path)

    docs, logs = get_dashboard_data(session["role"])
    return render_template("dashboard.html", docs=docs, logs=logs, verify_result=verify_res)

@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt_route():
    if not has_permission(session["role"], "ENCRYPT"):
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

@app.route("/download-seal/<int:doc_id>")
@login_required
def download_seal(doc_id: int):
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

    return send_file(seal_path, as_attachment=True)

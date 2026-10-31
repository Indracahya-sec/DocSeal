import hashlib
import hmac
import secrets
from typing import Optional, Dict, Any
from src.database.connection import get_db_connection
from src.core.audit import log_action

# Matriks Hak Akses (Role-Based Access Control)
ROLE_PERMISSIONS = {
    "admin": {"UPLOAD", "VERIFY", "ENCRYPT", "DECRYPT", "VIEW_LOGS", "MANAGE_USERS"},
    "operator": {"UPLOAD", "VERIFY", "ENCRYPT", "DECRYPT"},
    "staf": {"VERIFY"},
    "auditor": {"VERIFY", "VIEW_LOGS"},
}


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Mengacak password dengan PBKDF2-HMAC-SHA256 + Salt (100.000 iterasi)."""
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()
    return f"{salt}${pwd_hash}"


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Memvalidasi password input terhadap hash yang tersimpan di database."""
    try:
        salt, _ = stored_password.split("$")
        expected_hash = hash_password(provided_password, salt)
        # compare_digest mencegah Timing Attack saat membandingkan string hash
        return hmac.compare_digest(stored_password, expected_hash)
    except ValueError:
        return False


def has_permission(role: str, action: str) -> bool:
    """Mengecek apakah role tertentu diizinkan melakukan aksi terkait."""
    allowed_actions = ROLE_PERMISSIONS.get(role.lower(), set())
    return action.upper() in allowed_actions


MAX_FAILED_ATTEMPTS = 5


def is_account_locked(username: str) -> bool:
    """
    Mengecek apakah akun terkunci sementara akibat >= 5 percobaan login gagal beruntun
    dalam 15 menit terakhir (Proteksi Brute-Force).
    """
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT a.status_result
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.user_id
        WHERE a.action = 'LOGIN'
          AND (u.username = ? OR a.details LIKE ?)
          AND a.timestamp >= datetime('now', '-15 minutes')
        ORDER BY a.log_id DESC
        LIMIT ?
        """,
        (username, f"%username: {username}", MAX_FAILED_ATTEMPTS),
    ).fetchall()
    conn.close()

    if len(rows) < MAX_FAILED_ATTEMPTS:
        return False

    return all(r["status_result"] in ("FAILED", "LOCKED_BRUTEFORCE") for r in rows)


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Memverifikasi kredensial login pengguna dan mencatatnya ke Audit Log."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if is_account_locked(username):
        locked_uid = user["user_id"] if user else None
        log_action(
            user_id=locked_uid,
            action="LOGIN",
            status_result="LOCKED_BRUTEFORCE",
            details=f"Akun '{username}' dikunci sementara karena >= {MAX_FAILED_ATTEMPTS} gagal login beruntun",
        )
        return None

    if user and verify_password(user["password_hash"], password):
        log_action(
            user_id=user["user_id"],
            action="LOGIN",
            status_result="SUCCESS",
            details=f"Login berhasil sebagai {user['role']}",
        )
        return dict(user)

    # Catat percobaan login gagal (penting untuk deteksi brute-force saat audit)
    failed_uid = user["user_id"] if user else None
    log_action(
        user_id=failed_uid,
        action="LOGIN",
        status_result="FAILED",
        details=f"Percobaan login gagal untuk username: {username}",
    )
    return None


def list_users() -> list[Dict[str, Any]]:
    """Mengambil daftar seluruh akun pengguna di sistem."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT user_id, username, role, created_at FROM users ORDER BY user_id ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_user(
    username: str, password: str, role: str, actor_user_id: int
) -> Dict[str, Any]:
    """Menambahkan akun pengguna baru oleh Admin dan mencatatnya ke Audit Log."""
    clean_user = username.strip()
    clean_role = role.strip().lower()

    if not clean_user or len(password) < 4:
        raise ValueError("Username wajib diisi dan password minimal 4 karakter.")

    if clean_role not in ROLE_PERMISSIONS:
        raise ValueError(
            f"Role '{role}' tidak valid. Pilih: {', '.join(ROLE_PERMISSIONS.keys())}"
        )

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE username = ?", (clean_user,))
    if cursor.fetchone():
        conn.close()
        log_action(
            user_id=actor_user_id,
            action="MANAGE_USERS",
            status_result="FAILED_DUPLICATE",
            details=f"Gagal membuat user '{clean_user}': Username sudah terdaftar",
        )
        raise ValueError(f"Username '{clean_user}' sudah terdaftar di sistem.")

    pwd_hash = hash_password(password)
    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (clean_user, pwd_hash, clean_role),
    )
    new_uid = cursor.lastrowid
    conn.commit()
    conn.close()

    log_action(
        user_id=actor_user_id,
        action="MANAGE_USERS",
        status_result="USER_CREATED",
        details=f"Akun baru '{clean_user}' (role: {clean_role}) dibuat dengan ID {new_uid}",
    )

    return {
        "user_id": new_uid,
        "username": clean_user,
        "role": clean_role,
        "message": f"Akun '{clean_user}' ({clean_role}) berhasil dibuat.",
    }

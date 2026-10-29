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


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Memverifikasi kredensial login pengguna dan mencatatnya ke Audit Log."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

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

import hashlib
import hmac
import secrets
from typing import Any

from src.core.audit import log_action
from src.database.connection import db_session

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"UPLOAD", "VERIFY", "ENCRYPT", "DECRYPT", "VIEW_LOGS", "MANAGE_USERS"},
    "operator": {"UPLOAD", "VERIFY", "ENCRYPT", "DECRYPT"},
    "staf": {"VERIFY"},
    "auditor": {"VERIFY", "VIEW_LOGS"},
}

MAX_FAILED_ATTEMPTS = 5


def hash_password(password: str, salt: str | None = None) -> str:
    """Mengacak password dengan PBKDF2-HMAC-SHA256 + Salt (100.000 iterasi)."""
    salt = salt or secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${pwd_hash}"


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Memvalidasi password input terhadap hash yang tersimpan dengan proteksi Timing Attack."""
    if "$" not in stored_password:
        return False
    salt, _ = stored_password.split("$", 1)
    return hmac.compare_digest(stored_password, hash_password(provided_password, salt))


def has_permission(role: str, action: str) -> bool:
    """Mengecek apakah role tertentu diizinkan melakukan aksi terkait."""
    return action.upper() in ROLE_PERMISSIONS.get(role.lower(), set())


def is_account_locked(username: str) -> bool:
    """Mengecek apakah akun terkunci akibat >= 5 gagal login beruntun dalam 15 menit terakhir."""
    with db_session() as conn:
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

    return len(rows) >= MAX_FAILED_ATTEMPTS and all(
        r["status_result"] in {"FAILED", "LOCKED_BRUTEFORCE"} for r in rows
    )


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    """Memverifikasi kredensial login pengguna dan mencatatnya ke Audit Log."""
    with db_session() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    uid = user["user_id"] if user else None

    if is_account_locked(username):
        log_action(
            uid,
            "LOGIN",
            "LOCKED_BRUTEFORCE",
            details=f"Akun '{username}' dikunci sementara karena >= {MAX_FAILED_ATTEMPTS} gagal login beruntun",
        )
        return None

    if user and verify_password(user["password_hash"], password):
        log_action(uid, "LOGIN", "SUCCESS", details=f"Login berhasil sebagai {user['role']}")
        return dict(user)

    log_action(uid, "LOGIN", "FAILED", details=f"Percobaan login gagal untuk username: {username}")
    return None


def list_users() -> list[dict[str, Any]]:
    """Mengambil daftar seluruh akun pengguna di sistem."""
    with db_session() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT user_id, username, role, created_at FROM users ORDER BY user_id ASC"
            )
        ]


def create_user(
    username: str, password: str, role: str, actor_user_id: int
) -> dict[str, Any]:
    """Menambahkan akun pengguna baru oleh Admin dan mencatatnya ke Audit Log."""
    clean_user, clean_role = username.strip(), role.strip().lower()

    if not clean_user or len(password) < 4:
        raise ValueError("Username wajib diisi dan password minimal 4 karakter.")
    if clean_role not in ROLE_PERMISSIONS:
        raise ValueError(f"Role '{role}' tidak valid. Pilih: {', '.join(ROLE_PERMISSIONS)}")

    with db_session() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (clean_user,)).fetchone():
            duplicate = True
            new_uid = None
        else:
            duplicate = False
            new_uid = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (clean_user, hash_password(password), clean_role),
            ).lastrowid

    if duplicate:
        log_action(
            actor_user_id,
            "MANAGE_USERS",
            "FAILED_DUPLICATE",
            details=f"Gagal membuat user '{clean_user}': Username sudah terdaftar",
        )
        raise ValueError(f"Username '{clean_user}' sudah terdaftar di sistem.")

    log_action(
        actor_user_id,
        "MANAGE_USERS",
        "USER_CREATED",
        details=f"Akun baru '{clean_user}' (role: {clean_role}) dibuat dengan ID {new_uid}",
    )
    return {
        "user_id": new_uid,
        "username": clean_user,
        "role": clean_role,
        "message": f"Akun '{clean_user}' ({clean_role}) berhasil dibuat.",
    }


def change_password(user_id: int, old_password: str, new_password: str) -> dict[str, Any]:
    """Mengubah password pengguna setelah memverifikasi password lama dengan proteksi timing attack."""
    if len(new_password) < 4:
        raise ValueError("Password baru minimal harus terdiri dari 4 karakter.")

    with db_session() as conn:
        user = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise ValueError("Akun pengguna tidak ditemukan.")

        if not verify_password(user["password_hash"], old_password):
            invalid_old = True
        else:
            invalid_old = False
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (hash_password(new_password), user_id),
            )

    if invalid_old:
        log_action(
            user_id,
            "CHANGE_PASSWORD",
            "FAILED_WRONG_PASSWORD",
            details=f"Gagal ganti password untuk '{user['username']}': Password lama tidak cocok",
        )
        raise ValueError("Password lama yang dimasukkan salah.")

    log_action(
        user_id,
        "CHANGE_PASSWORD",
        "SUCCESS",
        details=f"Password akun '{user['username']}' berhasil diperbarui",
    )
    return {
        "user_id": user_id,
        "username": user["username"],
        "message": f"Password untuk akun '{user['username']}' berhasil diperbarui.",
    }

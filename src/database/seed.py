from src.core.rbac import hash_password
from src.database.connection import db_session
from src.database.models import init_db

DEFAULT_USERS = (
    ("admin", "admin123", "admin"),
    ("operator", "operator123", "operator"),
    ("staf", "staf123", "staf"),
    ("auditor", "auditor123", "auditor"),
)


def seed_database() -> None:
    """Membuat skema tabel dan mengisi 4 akun default jika belum ada."""
    init_db()
    with db_session() as conn:
        for username, password, role in DEFAULT_USERS:
            exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, hash_password(password), role),
                )
            tag, label = ("=", "sudah ada") if exists else ("+", "default dibuat")
            print(f"[{tag}] Akun {label}: {username} ({role})")


if __name__ == "__main__":
    seed_database()

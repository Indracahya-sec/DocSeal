from src.database.connection import get_db_connection
from src.database.models import init_db
from src.core.rbac import hash_password

DEFAULT_USERS = [
    ("admin", "admin123", "admin"),
    ("operator", "operator123", "operator"),
    ("staf", "staf123", "staf"),
    ("auditor", "auditor123", "auditor"),
]


def seed_database() -> None:
    """Membuat skema tabel dan mengisi 4 akun default jika belum ada."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    for username, password, role in DEFAULT_USERS:
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            pwd_hash = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, pwd_hash, role),
            )
            print(f"[+] Akun default dibuat: {username} ({role})")
        else:
            print(f"[=] Akun sudah ada: {username} ({role})")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    seed_database()

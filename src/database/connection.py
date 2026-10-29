import sqlite3
from src.config import DB_PATH, ensure_directories


def get_db_connection() -> sqlite3.Connection:
    """Membuka koneksi ke database SQLite3 lokal."""
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    # Mengubah hasil query dari tuple (row[0]) menjadi dictionary-like (row['username'])
    conn.row_factory = sqlite3.Row
    # Mengaktifkan fitur Foreign Key di SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

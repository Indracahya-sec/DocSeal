import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from src.config import DB_PATH, ensure_directories


def get_db_connection() -> sqlite3.Connection:
    """Membuka koneksi ke database SQLite3 lokal dengan dukungan Row & Foreign Keys."""
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    """Context manager koneksi SQLite3 dengan auto-commit/rollback dan auto-close."""
    conn = get_db_connection()
    try:
        with conn:
            yield conn
    finally:
        conn.close()

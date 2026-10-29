from typing import Optional
from src.database.connection import get_db_connection


def log_action(
    user_id: Optional[int],
    action: str,
    status_result: str,
    doc_id: Optional[int] = None,
    details: str = "",
) -> None:
    """Mencatat setiap aktivitas pengguna ke tabel audit_logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_logs (user_id, action, doc_id, status_result, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, action.upper(), doc_id, status_result.upper(), details),
    )
    conn.commit()
    conn.close()

import csv
import io
from pathlib import Path
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


def export_audit_logs_csv(actor_user_id: int, output_path: Optional[str | Path] = None) -> str:
    """Mengekspor seluruh catatan Audit Trail ke format CSV dan mencatat aktivitas ekspor."""
    log_action(
        user_id=actor_user_id,
        action="EXPORT_LOGS",
        status_result="SUCCESS",
        details="Mengekspor laporan Audit Trail ke format CSV",
    )

    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT a.log_id, a.timestamp, COALESCE(u.username, 'UNKNOWN') as actor,
               COALESCE(u.role, '-') as role, a.action, a.doc_id, a.status_result, a.details
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.log_id DESC
        """
    ).fetchall()
    conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["log_id", "timestamp", "username", "role", "action", "doc_id", "status_result", "details"]
    )
    for r in rows:
        writer.writerow(
            [
                r["log_id"],
                r["timestamp"],
                r["actor"],
                r["role"],
                r["action"],
                r["doc_id"] if r["doc_id"] is not None else "",
                r["status_result"],
                r["details"],
            ]
        )

    csv_content = buffer.getvalue()
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(csv_content, encoding="utf-8")

    return csv_content

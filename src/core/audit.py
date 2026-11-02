import csv
import io
from pathlib import Path
from src.database.connection import db_session


def log_action(
    user_id: int | None,
    action: str,
    status_result: str,
    doc_id: int | None = None,
    details: str = "",
) -> None:
    """Mencatat setiap aktivitas pengguna ke tabel audit_logs."""
    with db_session() as conn:
        conn.execute(
            "INSERT INTO audit_logs (user_id, action, doc_id, status_result, details) VALUES (?, ?, ?, ?, ?)",
            (user_id, action.upper(), doc_id, status_result.upper(), details),
        )


def export_audit_logs_csv(
    actor_user_id: int, output_path: str | Path | None = None
) -> str:
    """Mengekspor seluruh catatan Audit Trail ke format CSV dan mencatat aktivitas ekspor."""
    log_action(
        actor_user_id,
        "EXPORT_LOGS",
        "SUCCESS",
        details="Mengekspor laporan Audit Trail ke format CSV",
    )

    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT a.log_id, a.timestamp, COALESCE(u.username, 'UNKNOWN') AS actor,
                   COALESCE(u.role, '-') AS role, a.action, a.doc_id, a.status_result, a.details
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            ORDER BY a.log_id DESC
            """
        ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["log_id", "timestamp", "username", "role", "action", "doc_id", "status_result", "details"]
    )
    writer.writerows(
        [
            r["log_id"],
            r["timestamp"],
            r["actor"],
            r["role"],
            r["action"],
            "" if r["doc_id"] is None else r["doc_id"],
            r["status_result"],
            r["details"],
        ]
        for r in rows
    )

    csv_content = buffer.getvalue()
    if output_path and (out := Path(output_path)):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(csv_content, encoding="utf-8")

    return csv_content

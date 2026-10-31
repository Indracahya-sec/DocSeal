from src.database.connection import get_db_connection


def init_db() -> None:
    """Membuat tabel users, documents, dan audit_logs jika belum ada."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Tabel Users (Mendukung RBAC 4 Role)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'staf', 'auditor')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # 2. Tabel Documents (Menyimpan Hash SHA-256 & Versi Dokumen)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            uploaded_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
        );
    """)

    # 3. Tabel Audit Logs (Mencatat Jejak Aktivitas)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            doc_id INTEGER,
            status_result TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (doc_id) REFERENCES documents(doc_id)
        );
    """)

    # 4. Trigger Immutable Audit Trail (Mencegah UPDATE dan DELETE pada audit_logs)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
        BEFORE UPDATE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'Audit logs bersifat immutable dan tidak dapat diubah!');
        END;
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
        BEFORE DELETE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'Audit logs bersifat immutable dan tidak dapat dihapus!');
        END;
    """)

    conn.commit()
    conn.close()

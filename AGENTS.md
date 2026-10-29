# Project Context: DocSeal (Digital Document Protection & Integrity Tool)

## Overview
DocSeal adalah sistem perlindungan, pemeriksaan integritas, dan pelacakan aktivitas dokumen digital lokal (on-premise) berbasis Python dengan pengujian menggunakan data dummy.

## Tech Stack
- Language: Python 3.x
- Database: SQLite3 (`sqlite3` built-in) -> disimpan di `data/docseal.db`
- Hashing: SHA-256 (`hashlib` built-in)
- Encryption: AES-256 (`cryptography` library)
- Interfaces: 
  1. CLI / Terminal (`argparse`) di `src/cli/main_cli.py`
  2. Web UI Lokal (`Flask` + HTML/Tailwind/Bootstrap) di `src/web/app.py`
- Testing: `pytest` menggunakan 100% data dummy di `data/dummy_docs/`

## Architecture & Directory Rules
- `src/config.py`: Mengatur semua path (`BASE_DIR`, `DB_PATH`, `DUMMY_DIR`, `ENCRYPTED_DIR`) dan `SECRET_KEY` Flask.
- `src/database/`: Koneksi SQLite3 (`connection.py`), skema tabel (`models.py`), dan akun awal (`seed.py`).
- `src/core/`: Logika keamanan inti (independen dari UI, dipakai bersama oleh CLI dan Web):
  - `hasher.py`: Hitung fingerprint SHA-256 per 4KB chunk, deteksi perubahan & duplikat, serta auto-versioning (v1.0, v2.0).
  - `crypto.py`: Enkripsi & dekripsi dokumen menggunakan AES-256 dengan ekstensi `.seal`.
  - `rbac.py`: Autentikasi dan pembatasan hak akses untuk 4 peran (Admin, Operator, Staf, Auditor).
  - `audit.py`: Pencatatan audit trail (siapa, kapan, dan tindakan terhadap dokumen) ke tabel `audit_logs`.
- `src/web/`: Aplikasi Flask (`app.py`) beserta file HTML di `templates/` dan aset di `static/`.

## Coding Guidelines
1. Gunakan Type Hints, Docstring singkat, dan error handling (`try-except`) yang rapi.
2. Setiap aktivitas (LOGIN, UPLOAD, VERIFY, ENCRYPT, DECRYPT) WAJIB memanggil fungsi pencatat di `src/core/audit.py`.
3. Semua aset CSS/JS harus bisa berjalan secara lokal/offline (on-premise).

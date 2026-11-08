---
name: clean-secure-python
description: Standar penulisan kode Python bebas AI-slop, validasi data ketat, dan audit keamanan untuk DocSeal.
---

# Clean Code & Security Validation Skill

Gunakan prosedur ini setiap kali menulis fitur baru atau melakukan refactoring kode.

## 1. Aturan Anti-Slop (Efisiensi Kode)
- **Zero Redundancy:** Dilarang menulis ulang logika koneksi database atau pembacaan file jika sudah ada fungsi helper di `src/`.
- **Strict Error Handling:** Dilarang menggunakan `except Exception:` buta. Tangkap exception spesifik (`ValueError`, `sqlite3.Error`, `InvalidTag`).
- **Flat Logic:** Gunakan *guard clauses* (early return) agar indentasi maksimal 3 level.
- **No Obvious Comments:** Hapus komentar yang hanya menjelaskan sintaks dasar. Tulis docstring singkat hanya untuk menjelaskan *mengapa* (konteks keamanan), bukan *apa*.

## 2. Standar Validasi Data & Input
- **Path Sanitization:** Setiap input path/filename dari user wajib diekstrak menggunakan `Path(filename).name` dan divalidasi tetap berada di dalam direktori `data/` menggunakan `.resolve()`.
- **File Content Check:** Sebelum memproses unggahan PDF, verifikasi header 5 byte pertama (`file.read(5) == b"%PDF-"`) dan batasi ukuran file agar tidak memicu *Denial of Service* (DoS) memori.
- **SQL Parameterization:** Seluruh interaksi SQLite wajib menggunakan placeholder `?`. Dilarang keras menggunakan f-string di dalam string SQL.

## 3. Checklist Validasi Kriptografi & RBAC
- Bandingkan hash atau kredensial sensitif menggunakan `hmac.compare_digest()`.
- Gunakan modul `os.urandom()` atau `secrets` untuk pembangkitan *salt* dan *nonce* (dilarang menggunakan modul `random` standar).
- Pastikan setiap endpoint atau fungsi sensitif memeriksa izin role di `rbac.py` sebelum menyentuh database atau sistem file.

## 4. Verifikasi Wajib Sebelum Selesai
Setelah memodifikasi kode, jalankan urutan perintah ini dan perbaiki jika ada peringatan:
1. `ruff check src/ tests/` (cek kualitas kode & bug tersembunyi)
2. `bandit -r src/` (audit celah keamanan statis Python)
3. `python3 -m pytest -v` (pastikan unit test tetap lulus)
# DocSeal — Sistem Proteksi, Verifikasi Integritas, dan Tata Kelola Arsip Digital

**DocSeal** adalah sistem perlindungan dokumen digital berbasis *on-premise* lokal yang dirancang untuk menjaga keaslian berkas (*integrity*), kerahasiaan arsip sensitif (*confidentiality*), serta akuntabilitas aktivitas pengguna (*non-repudiation*).

Proyek ini dikembangkan untuk mata kuliah **Applied Cyber Security** dengan implementasi pada **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan**.

> **Catatan Etika & Keamanan Data:** Seluruh pengujian dan simulasi bawaan pada repositori ini menggunakan **100% Data Dummy (Fiktif)** pada lingkungan lokal terisolasi (*On-Premise Environment*) dan seluruh berkas di dalam folder `data/` dikecualikan dari repositori publik melalui `.gitignore`.

---

## Tim Pengembang
* **Indra**
* **Bagas**
* **Yosuanry**

---

## Fitur Keamanan & Operasional Utama

1. **SHA-256 Integrity Verification, Chunking, & Batch Scan:**
   * Menghitung sidik jari digital (*cryptographic hash*) berkas secara bertahap per blok `4096 bytes` (4 KB) untuk efisiensi memori dan mendeteksi modifikasi sekecil 1 bit (*Avalanche Effect*).
   * Dilengkapi fitur **Batch Integrity Scan** untuk memindai keutuhan seluruh arsip lokal sekaligus guna mendeteksi kehilangan file fisik (`MISSING`) atau manipulasi langsung di media penyimpanan (*Direct Disk Tampering* / `MODIFIED`).
   * **Cetak Berita Acara Verifikasi (PDF Resmi):** Menerbitkan dokumen Berita Acara Verifikasi berkop **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan** secara otomatis setelah pemeriksaan keaslian dokumen.
2. **Smart Deduplication & Auto-Versioning:**
   * Menolak pengunggahan ulang berkas yang memiliki nilai hash SHA-256 identik 100% meskipun nama filenya diubah.
   * Menaikkan versi dokumen secara otomatis (`v1` -> `v2`, dst.) apabila dokumen dengan nama entitas yang sama diperbarui isinya, tanpa menimpa file fisik versi sebelumnya.
3. **AES-256-GCM File Encryption & Decryption (`.seal`):**
   * Mengunci berkas sensitif (*Data-at-Rest*) menggunakan algoritma **AES-256 mode GCM (*Galois/Counter Mode*)** dengan penurunan kunci **PBKDF2-HMAC-SHA256** (100.000 iterasi, 16-byte *Salt*, dan 12-byte *Nonce*).
   * Dilengkapi *Authentication Tag* bawaan untuk menolak dekripsi jika *passphrase* salah atau file `.seal` telah dimodifikasi.
4. **Role-Based Access Control (RBAC), Ganti Password Mandiri, & Brute-Force Protection:**
   * Pembatasan hak akses ketat berdasarkan 4 peran fungsional instansi (`Admin`, `Operator`, `Staf`, `Auditor`), fitur manajemen pengguna (`MANAGE_USERS`) khusus Admin, serta fitur **Ganti Password Mandiri** untuk seluruh pegawai.
   * Pengamanan kredensial menggunakan *salted PBKDF2-HMAC-SHA256*, proteksi *Timing Attack* (`hmac.compare_digest`), serta penguncian akun sementara (*Account Lockout*) apabila terjadi ≥ 5 kali gagal login beruntun dalam 15 menit terakhir.
5. **Database-Enforced Immutable Audit Trail, CSV Export, & System Backup (`.ZIP`):**
   * Pencatatan jejak aktivitas bersifat *append-only* untuk melacak waktu, pelaku, jenis aksi (`LOGIN`, `LOGOUT`, `UPLOAD`, `VERIFY`, `EXPORT_CERTIFICATE`, `BATCH_SCAN`, `ENCRYPT`, `DECRYPT`, `DOWNLOAD_SEAL`, `MANAGE_USERS`, `CHANGE_PASSWORD`, `EXPORT_LOGS`, `SYSTEM_BACKUP`), dan status hasilnya (termasuk percobaan `ACCESS_DENIED`).
   * Dilindungi oleh **SQLite Triggers** (`BEFORE UPDATE` dan `BEFORE DELETE`) yang memblokir upaya modifikasi maupun penghapusan log secara paksa, mendukung ekspor laporan ke `.CSV`, serta fitur **Backup Sistem & Arsip Satu Klik (`.ZIP`)** khusus Admin.
6. **Input Validation & Anti-Path Traversal Hardening:**
   * Memverifikasi *magic header* 5-byte pertama berkas unggahan (`%PDF-`), membatasi ukuran maksimum berkas (`MAX_FILE_SIZE = 10 MB`) untuk mencegah *Memory Exhaustion DoS*, mengisolasi path menggunakan `Path.resolve().is_relative_to()`, dan menggunakan *SQL Parameterization* (`?`) 100%.
7. **Dual Interface (CLI & Local Web UI) + 1-Click Launcher:**
   * Dapat dioperasikan melalui antarmuka baris perintah (CLI) maupun antarmuka Web Lokal (Flask) bebas ketergantungan internet (*offline-ready*) melalui *launcher* satu klik (`Start_DocSeal.bat` untuk Windows dan `start_docseal.sh` untuk Linux).

---

## Struktur Arsitektur Proyek

```text
DocSeal/
├── main.py                              # Entry point utama Server Web UI Lokal
├── Start_DocSeal.bat                    # Launcher 1-klik untuk komputer Windows mitra
├── start_docseal.sh                     # Launcher 1-klik untuk komputer Linux/macOS
├── run_demo.py                          # Skrip simulasi otomatis end-to-end (1-click demo)
├── pytest.ini                           # Konfigurasi path pengujian otomatis pytest
├── requirements.txt                     # Daftar dependensi pustaka Python
├── docs/
│   ├── FLOWCHART_ARSITEKTUR.md          # Flowchart interaktif arsitektur & tautan baris kode
│   └── DOKUMEN_SERAH_TERIMA_MITRA.md    # Template BAST, Form UAT, & SOP untuk instansi mitra
├── data/
│   ├── docseal.db                       # Database SQLite3 lokal (Users, Documents, Audit Logs)
│   ├── dummy_docs/                      # Penyimpanan berkas PDF & Berita Acara Verifikasi
│   └── encrypted/                       # Penyimpanan berkas terenkripsi (.seal)
├── src/
│   ├── config.py                        # Konfigurasi path, batas ukuran file, & sanitasi path
│   ├── core/                            # Mesin kriptografi & logika keamanan inti
│   │   ├── audit.py                     # Pencatat audit_logs, ekspor CSV, & backup sistem (.zip)
│   │   ├── crypto.py                    # Enkripsi & dekripsi dokumen dengan AES-256-GCM
│   │   ├── hasher.py                    # Validasi header PDF, SHA-256, versioning, & batch scan
│   │   └── rbac.py                      # Autentikasi, ganti password, lockout, & matriks 4 role
│   ├── database/                        # Manajemen database SQLite3
│   │   ├── connection.py                # Context manager db_session() & PRAGMA foreign_keys
│   │   ├── models.py                    # Skema tabel & Trigger Immutable Audit Trail
│   │   └── seed.py                      # Inisialisasi skema & 4 akun default RBAC
│   ├── cli/
│   │   └── main_cli.py                  # Antarmuka Command Line Interface (argparse)
│   └── web/
│       ├── app.py                       # Backend server Web UI lokal (Flask)
│       └── templates/                   # Antarmuka HTML (login.html & dashboard.html)
└── tests/
    ├── generate_dummy.py                # Generator PDF dummy kustom & Berita Acara Verifikasi PDF
    ├── test_crypto.py                   # Unit test otomatis modul AES-256-GCM
    ├── test_hasher.py                   # Unit test otomatis modul SHA-256 & Versioning
    └── test_rbac_audit_web.py           # Unit test RBAC, Immutable Trigger, Hardening, & Mitra
```

* **Diagram Alur Kode Interaktif:** Lihat [docs/FLOWCHART_ARSITEKTUR.md](docs/FLOWCHART_ARSITEKTUR.md).
* **Dokumen BAST, Form UAT, & Panduan Dokumentasi Mitra:** Lihat [docs/DOKUMEN_SERAH_TERIMA_MITRA.md](docs/DOKUMEN_SERAH_TERIMA_MITRA.md).

---

## Matriks Hak Akses (RBAC) & Akun Default

Saat database diinisialisasi (`seed.py`), sistem menyediakan 4 akun bawaan dengan pembagian wewenang berikut:

| Role | Username | Password | Hak Akses Fitur (`ROLE_PERMISSIONS`) |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` | `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT`, `VIEW_LOGS`, `MANAGE_USERS` (+ Backup Sistem `.ZIP`) |
| **Operator** | `operator` | `operator123` | `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT` (+ Buat PDF Dummy & Cetak Berita Acara PDF) |
| **Staf** | `staf` | `staf123` | `VERIFY` (Verifikasi dokumen satuan, Cetak Berita Acara PDF, & Batch Integrity Scan) |
| **Auditor** | `auditor` | `auditor123` | `VERIFY`, `VIEW_LOGS` (Pemeriksaan keaslian, Batch Scan, & ekspor laporan Audit Trail `.CSV`) |

---

## Cara Instalasi & Menjalankan Sistem

### A. Menjalankan Cepat dengan Launcher Satu Klik
* **Linux / macOS:**
  ```bash
  ./start_docseal.sh
  ```
* **Windows (PC Kantor Mitra):**
  Klik 2x pada berkas **`Start_DocSeal.bat`**.

### B. Instalasi Manual dari Awal
1. **Masuk ke direktori proyek dan aktifkan *Virtual Environment* (`venv`):**
   ```bash
   cd ~/Desktop/DocSeal
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Inisialisasi Database SQLite3 & Akun Default RBAC:**
   ```bash
   python3 -m src.database.seed
   ```

3. **Bangkitkan Berkas PDF Dummy untuk Pengujian:**
   ```bash
   python3 -m tests.generate_dummy --default
   python3 -m tests.generate_dummy -n "Surat_Rekomendasi_01" -i "Nama: I Ketut Simulasi\nAlamat: Tabanan"
   ```

4. **Jalankan Server Web UI Lokal (`http://127.0.0.1:5000`):**
   ```bash
   python3 main.py
   ```

---

## Panduan Penggunaan Antarmuka CLI (Terminal)

```bash
# 1. Buat berkas PDF Dummy kustom langsung dari CLI
python3 -m src.cli.main_cli make-dummy -n "Berkas_Jamaah_Tabanan" -i "Nama: I Made Simulasi\nPorsi: 5100099901"

# 2. Unggah dokumen asli oleh Operator (v1)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01.pdf -n "Berkas_Jamaah_01"

# 3. Uji unggah duplikat identik (Otomatis ditolak oleh sistem)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01_Copy.pdf -n "Berkas_Jamaah_01"

# 4. Uji unggah dokumen revisi (Otomatis naik versi menjadi v2)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01_Revisi.pdf -n "Berkas_Jamaah_01"

# 5. Lihat daftar dokumen yang terdaftar di database
python3 -m src.cli.main_cli list

# 6. Verifikasi integritas dokumen & sekaligus cetak Berita Acara Verifikasi resmi (--cert)
python3 -m src.cli.main_cli verify -u staf -p staf123 -i 1 -f data/dummy_docs/Berkas_Jamaah_01.pdf --cert

# 7. Pindai keutuhan seluruh arsip dokumen sekaligus (Batch Integrity Scan)
python3 -m src.cli.main_cli scan -u staf -p staf123

# 8. Enkripsi dokumen ke format .seal (AES-256-GCM) & Dekripsi kembali ke PDF
python3 -m src.cli.main_cli encrypt -u operator -p operator123 -i 1 -k "rahasiahaji"
python3 -m src.cli.main_cli decrypt -u operator -p operator123 -i 1 -f data/encrypted/Berkas_Jamaah_01_v1.seal -o data/dummy_docs/Hasil_Dekripsi.pdf -k "rahasiahaji"

# 9. Kelola akun pengguna RBAC & Ganti Password Mandiri
python3 -m src.cli.main_cli users -u admin -p admin123
python3 -m src.cli.main_cli add-user -u admin -p admin123 --new-user staf_tabanan --new-pass staf1234 --role staf
python3 -m src.cli.main_cli change-password -u staf_tabanan -p staf1234 --new-pass staf_baru_2026

# 10. Ekspor laporan Audit Trail (.CSV) & Backup Sistem Lengkap (.ZIP)
python3 -m src.cli.main_cli logs -u auditor -p auditor123
python3 -m src.cli.main_cli export-logs -u auditor -p auditor123 -o data/DocSeal_Audit_Trail.csv
python3 -m src.cli.main_cli backup -u admin -p admin123 -o data/DocSeal_System_Backup.zip
```

---

## Pengujian Otomatis & Validasi Keamanan Kode

Proyek ini telah dilengkapi rangkaian verifikasi fungsional, *linter*, dan pemindaian keamanan statis (*SAST*):

```bash
./venv/bin/ruff check src/ tests/
./venv/bin/bandit -r src/
./venv/bin/python -m pytest -v
```

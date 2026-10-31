# DocSeal — Sistem Proteksi, Verifikasi Integritas, dan Tata Kelola Arsip Digital

**DocSeal** adalah sistem perlindungan dokumen digital berbasis *on-premise* lokal yang dirancang untuk menjaga keaslian berkas (*integrity*), kerahasiaan arsip sensitif (*confidentiality*), serta akuntabilitas aktivitas pengguna (*non-repudiation*).

Proyek ini dikembangkan sebagai pemenuhan tugas mata kuliah **Applied Cyber Security** dengan studi kasus simulasi tata kelola arsip digital pada **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan**.

> **Catatan Etika & Keamanan Data:** Seluruh pengujian dan simulasi pada repositori ini menggunakan **100% Data Dummy (Fiktif)** pada lingkungan lokal terisolasi (*Simulated On-Premise Environment*) dan tidak memuat data pribadi jamaah asli.

---

## Tim Pengembang
* **Indra**
* **Bagas**
* **Yosuanry**

---

## Fitur Keamanan Utama

1. **SHA-256 Integrity Verification, Chunking, & Batch Scan:**
   * Menghitung sidik jari digital (*cryptographic hash*) berkas secara bertahap per blok `4096 bytes` (4 KB) untuk efisiensi memori dan mendeteksi modifikasi sekecil 1 bit (*Avalanche Effect*).
   * Dilengkapi fitur **Batch Integrity Scan** untuk memindai keutuhan seluruh arsip lokal sekaligus guna mendeteksi kehilangan file fisik (`MISSING`) atau manipulasi langsung di media penyimpanan (*Direct Disk Tampering* / `MODIFIED`).
2. **Smart Deduplication & Auto-Versioning:**
   * Menolak pengunggahan ulang berkas yang memiliki nilai hash SHA-256 identik 100% meskipun nama filenya diubah.
   * Menaikkan versi dokumen secara otomatis (`v1` -> `v2`, dst.) apabila dokumen dengan nama entitas yang sama diperbarui isinya, tanpa menimpa file fisik versi sebelumnya.
3. **AES-256-GCM File Encryption & Decryption (`.seal`):**
   * Mengunci berkas sensitif (*Data-at-Rest*) menggunakan algoritma **AES-256 mode GCM (*Galois/Counter Mode*)** dengan penurunan kunci **PBKDF2-HMAC-SHA256** (100.000 iterasi, 16-byte *Salt*, dan 12-byte *Nonce*).
   * Dilengkapi *Authentication Tag* bawaan untuk menolak dekripsi jika *passphrase* salah atau file `.seal` telah dimodifikasi.
4. **Role-Based Access Control (RBAC) & Brute-Force Protection:**
   * Pembatasan hak akses ketat berdasarkan 4 peran fungsional instansi (`Admin`, `Operator`, `Staf`, `Auditor`) beserta fitur manajemen pengguna (`MANAGE_USERS`) khusus Admin.
   * Pengamanan kredensial menggunakan *salted PBKDF2-HMAC-SHA256*, proteksi *Timing Attack* (`hmac.compare_digest`), serta penguncian akun sementara (*Account Lockout*) apabila terjadi ≥ 5 kali gagal login beruntun dalam 15 menit terakhir.
5. **Database-Enforced Immutable Audit Trail & CSV Export:**
   * Pencatatan jejak aktivitas bersifat *append-only* untuk melacak waktu, pelaku, jenis aksi (`LOGIN`, `LOGOUT`, `UPLOAD`, `VERIFY`, `BATCH_SCAN`, `ENCRYPT`, `DECRYPT`, `DOWNLOAD_SEAL`, `MANAGE_USERS`, `EXPORT_LOGS`), dan status hasilnya (termasuk percobaan `ACCESS_DENIED`).
   * Dilindungi oleh **SQLite Triggers** (`BEFORE UPDATE` dan `BEFORE DELETE`) yang memblokir upaya modifikasi maupun penghapusan log secara paksa, serta mendukung ekspor laporan ke format `.CSV`.
6. **Dual Interface (CLI & Local Web UI):** Dapat dioperasikan melalui antarmuka baris perintah (CLI) untuk administrator/otomasi maupun antarmuka Web Lokal (Flask) bebas ketergantungan internet (*offline-ready*) untuk pegawai.

---

## Struktur Arsitektur Proyek

```text
DocSeal/
├── AGENTS.md                  # Panduan konteks & spesifikasi arsitektur sistem
├── main.py                    # Entry point utama untuk menjalankan Server Web UI Lokal
├── run_demo.py                # Skrip simulasi otomatis end-to-end (1-click demo)
├── pytest.ini                 # Konfigurasi path pengujian otomatis pytest
├── requirements.txt           # Daftar dependensi pustaka Python
├── data/
│   ├── docseal.db             # Database SQLite3 lokal (Users, Documents, Audit Logs)
│   ├── dummy_docs/            # Penyimpanan berkas PDF dummy hasil simulasi
│   └── encrypted/             # Penyimpanan berkas terenkripsi (.seal)
├── src/
│   ├── config.py              # Konfigurasi path absolut dinamis & kunci aplikasi
│   ├── core/                  # Mesin kriptografi & logika keamanan inti
│   │   ├── audit.py           # Pencatat aktivitas ke audit_logs & ekspor laporan CSV
│   │   ├── crypto.py          # Enkripsi & dekripsi dokumen dengan AES-256-GCM
│   │   ├── hasher.py          # Mesin SHA-256, deduplikasi, versioning, & batch scan
│   │   └── rbac.py            # Autentikasi, brute-force lockout, & matriks izin 4 role
│   ├── database/              # Manajemen database SQLite3
│   │   ├── connection.py      # Koneksi database dengan PRAGMA foreign_keys
│   │   ├── models.py          # Skema tabel & Trigger Immutable Audit Trail
│   │   └── seed.py            # Inisialisasi skema & 4 akun default RBAC
│   ├── cli/
│   │   └── main_cli.py        # Antarmuka Command Line Interface (argparse)
│   └── web/
│       ├── app.py             # Backend server Web UI lokal (Flask)
│       └── templates/         # Antarmuka HTML (login.html & dashboard.html)
└── tests/
    ├── generate_dummy.py      # Generator otomatis berkas PDF data dummy
    ├── test_crypto.py         # Unit test otomatis modul AES-256-GCM
    ├── test_hasher.py         # Unit test otomatis modul SHA-256 & Versioning
    └── test_rbac_audit_web.py # Unit test RBAC, Immutable Trigger, Batch Scan, & Web UI
```

---

## Matriks Hak Akses (RBAC) & Akun Default Simulasi

Saat database diinisialisasi (`seed.py`), sistem menyediakan 4 akun simulasi dengan pembagian wewenang berikut:

| Role | Username | Password | Hak Akses Fitur (`ROLE_PERMISSIONS`) |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` | `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT`, `VIEW_LOGS`, `MANAGE_USERS` |
| **Operator** | `operator` | `operator123` | `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT` |
| **Staf** | `staf` | `staf123` | `VERIFY` (Verifikasi dokumen satuan & Batch Integrity Scan) |
| **Auditor** | `auditor` | `auditor123` | `VERIFY`, `VIEW_LOGS` (Pemeriksaan keaslian & ekspor laporan Audit Trail CSV) |

---

## Cara Instalasi & Persiapan Lingkungan

1. **Masuk ke direktori proyek dan buat *Virtual Environment* (`venv`):**
   ```bash
   cd ~/Desktop/DocSeal
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Instal seluruh dependensi pustaka:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Inisialisasi Database SQLite3 & Akun Default RBAC:**
   ```bash
   python3 -m src.database.seed
   ```

4. **Bangkitkan Berkas PDF Dummy untuk Pengujian:**
   ```bash
   python3 -m tests.generate_dummy
   ```
   *(Menghasilkan `Berkas_Jamaah_01.pdf`, `Berkas_Jamaah_01_Copy.pdf`, dan `Berkas_Jamaah_01_Revisi.pdf` di dalam folder `data/dummy_docs/`).*

---

## Simulasi Otomatis Satu Klik (*End-to-End Demo*)

Untuk menjalankan demonstrasi seluruh fitur secara otomatis (Reset DB -> Seed -> Generate PDF Dummy -> Upload `v1` -> Tolak Duplikat -> Upload Revisi `v2` -> Verifikasi Valid vs Modified -> Batch Scan -> Enkripsi & Dekripsi AES-256-GCM -> Ekspor Audit CSV):

```bash
python3 run_demo.py
```

---

## Panduan Penggunaan Antarmuka Web UI Lokal

Jalankan server Flask lokal dari *root directory* proyek:

```bash
python3 main.py
```

Buka peramban (*browser*) dan akses alamat: **`http://127.0.0.1:5000`**
* Login menggunakan salah satu akun RBAC di atas untuk menguji:
  1. **Unggah & Registrasi Dokumen** (SHA-256, Deduplikasi, & Auto-Versioning).
  2. **Verifikasi Keaslian Satuan & Batch Integrity Scan** seluruh arsip lokal.
  3. **Enkripsi Dokumen Sensitif** ke format `.seal` (AES-256-GCM) dan pengunduhan arsip `.seal`.
  4. **Dekripsi Arsip `.seal`** kembali ke dokumen asli langsung dari browser.
  5. **Manajemen Pengguna RBAC** (Khusus Admin) & **Unduh Laporan Audit Trail `.CSV`** (Khusus Admin & Auditor).

---

## Panduan Penggunaan Antarmuka CLI (Terminal)

Seluruh fitur juga dapat diakses langsung melalui terminal:

```bash
# 1. Unggah dokumen asli oleh Operator
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01.pdf -n "Berkas_Jamaah_01"

# 2. Uji unggah duplikat identik (Otomatis ditolak oleh sistem)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01_Copy.pdf -n "Berkas_Jamaah_01"

# 3. Uji unggah dokumen revisi (Otomatis naik versi menjadi v2)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01_Revisi.pdf -n "Berkas_Jamaah_01"

# 4. Lihat daftar dokumen yang terdaftar di database
python3 -m src.cli.main_cli list

# 5. Verifikasi integritas dokumen satuan oleh Staf (Hasil: VALID vs MODIFIED)
python3 -m src.cli.main_cli verify -u staf -p staf123 -i 1 -f data/dummy_docs/Berkas_Jamaah_01.pdf
python3 -m src.cli.main_cli verify -u staf -p staf123 -i 1 -f data/dummy_docs/Berkas_Jamaah_01_Revisi.pdf

# 6. Pindai keutuhan seluruh arsip dokumen sekaligus (Batch Integrity Scan)
python3 -m src.cli.main_cli scan -u staf -p staf123

# 7. Enkripsi dokumen ke format .seal (AES-256-GCM)
python3 -m src.cli.main_cli encrypt -u operator -p operator123 -i 1 -k "rahasiahaji"

# 8. Dekripsi file .seal kembali ke PDF utuh
python3 -m src.cli.main_cli decrypt -u operator -p operator123 -i 1 -f data/encrypted/Berkas_Jamaah_01_v1.seal -o data/dummy_docs/Hasil_Dekripsi.pdf -k "rahasiahaji"

# 9. Kelola akun pengguna RBAC (Khusus Admin)
python3 -m src.cli.main_cli users -u admin -p admin123
python3 -m src.cli.main_cli add-user -u admin -p admin123 --new-user staf_tabanan --new-pass staf1234 --role staf

# 10. Tampilkan & ekspor riwayat Audit Trail ke CSV (Khusus Admin & Auditor)
python3 -m src.cli.main_cli logs -u auditor -p auditor123
python3 -m src.cli.main_cli export-logs -u auditor -p auditor123 -o data/DocSeal_Audit_Trail.csv
```

---

## Pengujian Unit Otomatis (*Automated Unit Testing*)

Untuk menjalankan seluruh *test suite* otomatis (SHA-256, Deduplikasi, Auto-Versioning, AES-256-GCM, RBAC, Brute-Force Lockout, SQLite Immutable Audit Trigger, Batch Scan, dan Web UI endpoints) menggunakan environment terisolasi:

```bash
pytest -v
```

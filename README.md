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

1. **SHA-256 Integrity Verification & Chunking:** Menghitung sidik jari digital (*cryptographic hash*) berkas secara bertahap per blok `4096 bytes`  (4 KB) untuk efisiensi memori dan mendeteksi modifikasi sekecil 1 bit (*Avalanche Effect*).
2. **Smart Deduplication & Auto-Versioning:**
   * Menolak pengunggahan ulang berkas yang memiliki nilai hash SHA-256 identik 100% meskipun nama filenya diubah.
   * Menaikkan versi dokumen secara otomatis (`v1` -> `v2`, dst.) apabila dokumen dengan nama entitas yang sama diperbarui isinya.
3. **AES-256-GCM File Encryption (`.seal`):** Mengunci berkas sensitif (*Data-at-Rest*) menggunakan algoritma **AES-256 mode GCM (*Galois/Counter Mode*)** dengan penurunan kunci **PBKDF2-HMAC-SHA256** (100.000 iterasi, 16-byte *Salt*, dan 12-byte *Nonce*). Dilengkapi *Authentication Tag* bawaan untuk menolak dekripsi jika *passphrase* salah atau file `.seal` dirusak.
4. **Role-Based Access Control (RBAC):** Pembatasan hak akses ketat berdasarkan 4 peran fungsional instansi (`Admin`, `Operator`, `Staf`, `Auditor`) dengan pengamanan kredensial menggunakan *salted PBKDF2-HMAC-SHA256* dan proteksi *Timing Attack* (`hmac.compare_digest`).
5. **Immutable Audit Trail Log:** Pencatatan jejak aktivitas bersifat *append-only* di database lokal untuk melacak waktu, pelaku, jenis aksi (`LOGIN`, `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT`), dan status hasilnya.
6. **Dual Interface (CLI & Local Web UI):** Dapat dioperasikan melalui antarmuka baris perintah (CLI) untuk administrator/otomasi maupun antarmuka Web Lokal (Flask) bebas ketergantungan internet (*offline-ready*) untuk pegawai.

---

## Struktur Arsitektur Proyek

```text
DocSeal/
├── AGENTS.md                  # Panduan konteks & spesifikasi arsitektur sistem
├── main.py                    # Entry point utama untuk menjalankan Server Web UI Lokal
├── requirements.txt           # Daftar dependensi pustaka Python
├── data/
│   ├── docseal.db             # Database SQLite3 lokal (Users, Documents, Audit Logs)
│   ├── dummy_docs/            # Penyimpanan berkas PDF dummy hasil simulasi
│   └── encrypted/             # Penyimpanan berkas terenkripsi (.seal)
├── src/
│   ├── config.py              # Konfigurasi path absolut dinamis & kunci aplikasi
│   ├── core/                  # Mesin kriptografi & logika keamanan inti
│   │   ├── audit.py           # Pencatat aktivitas ke tabel audit_logs
│   │   ├── crypto.py          # Enkripsi & dekripsi dokumen dengan AES-256-GCM
│   │   ├── hasher.py          # Mesin SHA-256, deduplikasi, & auto-versioning
│   │   └── rbac.py            # Autentikasi pengguna & matriks izin 4 role
│   ├── database/              # Manajemen database SQLite3
│   │   ├── connection.py      # Koneksi database dengan PRAGMA foreign_keys
│   │   ├── models.py          # Skema tabel users, documents, dan audit_logs
│   │   └── seed.py            # Inisialisasi skema & 4 akun default RBAC
│   ├── cli/
│   │   └── main_cli.py        # Antarmuka Command Line Interface (argparse)
│   └── web/
│       ├── app.py             # Backend server Web UI lokal (Flask)
│       └── templates/         # Antarmuka HTML (login.html & dashboard.html)
└── tests/
    ├── generate_dummy.py      # Generator otomatis berkas PDF data dummy
    ├── test_crypto.py         # Unit test otomatis modul AES-256-GCM
    └── test_hasher.py         # Unit test otomatis modul SHA-256 & Versioning
```

---

## Matriks Hak Akses (RBAC) & Akun Default Simulasi

Saat database diinisialisasi (`seed.py`), sistem menyediakan 4 akun simulasi dengan pembagian wewenang berikut:

| Role | Username | Password | Hak Akses Fitur (`PERMISSIONS`) |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` | `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT`, `VIEW_LOGS`, `MANAGE_USERS` |
| **Operator** | `operator` | `operator123` | `UPLOAD`, `VERIFY`, `ENCRYPT`, `DECRYPT` |
| **Staf** | `staf` | `staf123` | `VERIFY` (Hanya pemeriksaan keaslian dokumen) |
| **Auditor** | `auditor` | `auditor123` | `VERIFY`, `VIEW_LOGS` (Pemeriksaan keaslian & pemantauan Audit Trail) |

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

## Panduan Penggunaan Antarmuka Web UI Lokal

Jalankan server Flask lokal dari *root directory* proyek:

```bash
python3 main.py
```

Buka peramban (*browser*) dan akses alamat: **`http://127.0.0.1:5000`**
* Login menggunakan salah satu akun RBAC di atas untuk menguji pengunggahan dokumen, pemeriksaan keaslian SHA-256, penguncian AES-256-GCM (`.seal`), dan pemantauan tabel *Audit Trail*.

---

## Panduan Penggunaan Antarmuka CLI (Terminal)

Seluruh fitur inti juga dapat diakses langsung melalui terminal:

```bash
# 1. Unggah dokumen asli oleh Operator 
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01.pdf -n "Berkas_Jamaah_01"

# 2. Uji unggah duplikat identik (Otomatis ditolak oleh sistem)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01_Copy.pdf -n "Berkas_Jamaah_01"

# 3. Uji unggah dokumen revisi (Otomatis naik versi menjadi v2)
python3 -m src.cli.main_cli upload -u operator -p operator123 -f data/dummy_docs/Berkas_Jamaah_01_Revisi.pdf -n "Berkas_Jamaah_01"

# 4. Lihat daftar dokumen yang terdaftar di database
python3 -m src.cli.main_cli list

# 5. Verifikasi integritas dokumen oleh Staf (Hasil: VALID vs MODIFIED)
python3 -m src.cli.main_cli verify -u staf -p staf123 -i 1 -f data/dummy_docs/Berkas_Jamaah_01.pdf
python3 -m src.cli.main_cli verify -u staf -p staf123 -i 1 -f data/dummy_docs/Berkas_Jamaah_01_Revisi.pdf

# 6. Enkripsi dokumen ke format .seal (AES-256-GCM)
python3 -m src.cli.main_cli encrypt -u operator -p operator123 -i 1 -k "rahasiahaji"

# 7. Dekripsi file .seal kembali ke PDF utuh
python3 -m src.cli.main_cli decrypt -u operator -p operator123 -f data/encrypted/Berkas_Jamaah_01_v1.seal -o data/dummy_docs/Hasil_Dekripsi.pdf -k "rahasiahaji"

# 8. Tampilkan riwayat Audit Trail (Khusus Admin & Auditor)
python3 -m src.cli.main_cli logs -u auditor -p auditor123
```

---

## Pengujian Unit Otomatis (*Automated Unit Testing*)

Untuk menjalankan pengujian otomatis terhadap siklus hidup dokumen (SHA-256, deduplikasi, *auto-versioning*) serta keandalan enkripsi/dekripsi AES-256-GCM menggunakan database terisolasi sementara:

```bash
python3 -m pytest -v
```

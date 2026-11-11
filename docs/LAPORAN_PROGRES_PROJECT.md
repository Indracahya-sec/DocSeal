# LAPORAN PROGRES IMPLEMENTASI PROYEK APPLIED CYBER SECURITY

**Judul Proyek** : **DocSeal — Sistem Proteksi, Verifikasi Integritas SHA-256, Enkripsi AES-256-GCM, dan Audit Trail Dokumen Digital Berbasis On-Premise**  
**Tim Pengembang** : Indra, Bagas, Yosuanry  
**Repositori Kode** : https://github.com/Indracahya-sec/DocSeal  

---

## BAB I. GAMBARAN UMUM PROYEK (*PROJECT OVERVIEW*)

### 1.1 Latar Belakang Masalah
Dalam pengelolaan administrasi dan dokumen pelayanan publik—khususnya berkas pendaftaran, surat rekomendasi paspor, serta dokumen pelunasan dan manifest jamaah—risiko keamanan informasi yang paling sering terjadi meliputi:
1. **Modifikasi Dokumen Tanpa Izin (*Unauthorized Tampering*)**: Perubahan isi dokumen PDF (seperti nomor porsi, NIK, atau status berkas) yang sulit dideteksi secara kasat mata.
2. **Duplikasi dan Kebingungan Versi Berkas**: Pengunggahan berkas yang sama berulang kali atau tertimpanya dokumen asli oleh dokumen revisi tanpa pelacakan versi.
3. **Kebocoran Arsip Sensitif (*Data-at-Rest Exposure*)**: Berkas dokumen yang disimpan dalam bentuk teks terbuka (*plaintext*) pada komputer operasional rentan diakses oleh pihak yang tidak berwenang.
4. **Ketiadaan Jejak Akuntabilitas (*Lack of Non-Repudiation*)**: Sulitnya melacak siapa yang mengunggah, memeriksa, mengenkripsi, atau membuka dokumen pada waktu tertentu.

### 1.2 Solusi yang Dikembangkan (DocSeal)
**DocSeal** adalah sistem keamanan dokumen digital lokal (*On-Premise*) berbasis Python dan SQLite3 yang menerapkan tiga prinsip utama keamanan informasi (**CIA Triad + Non-Repudiation**):
1. **Integrity (Keutuhan & Keaslian Data)**:
   - Menggunakan algoritma *cryptographic hashing* **SHA-256** dengan pembacaan bertahap (*4KB chunking*) untuk menghasilkan sidik jari digital unik pada setiap dokumen ([src/core/hasher.py](../src/core/hasher.py)).
   - Dilengkapi fitur **Smart Deduplication** (menolak berkas yang 100% identik), **Auto-Versioning** (`v1`, `v2`, dst.), **Batch Integrity Scan** (pemindaian seluruh arsip lokal sekaligus), serta pencetakan otomatis **Berita Acara Verifikasi Integritas Dokumen (PDF Resmi)**.
2. **Confidentiality (Kerahasiaan Data)**:
   - Mengamankan arsip sensitif menjadi berkas terenkripsi berekstensi `.seal` menggunakan algoritma **AES-256 mode GCM (*Galois/Counter Mode*)** dengan penurunan kunci **PBKDF2-HMAC-SHA256** sebanyak **100.000 iterasi**, *Salt* acak 16-byte, dan *Nonce* 12-byte ([src/core/crypto.py](../src/core/crypto.py)).
   - Membatasi hak akses melalui **Role-Based Access Control (RBAC)** untuk 4 peran (**Admin, Operator, Staf, Auditor**) serta dilengkapi **Brute-Force Account Lockout** (penguncian akun otomatis selama 15 menit setelah 5 kali gagal login beruntun) ([src/core/rbac.py](../src/core/rbac.py)).
3. **Availability & Non-Repudiation (Ketersediaan & Jejak Audit)**:
   - Berjalan secara mandiri (*offline/on-premise*) tanpa ketergantungan internet melalui dua antarmuka: **Web UI Lokal (Flask)** dan **CLI (Terminal)**, dilengkapi fitur **Backup Sistem Satu Klik (`.ZIP`)**.
   - Mencatat seluruh aktivitas pengguna ke dalam tabel `audit_logs` yang dilindungi oleh **SQLite Immutable Triggers** (`BEFORE UPDATE` dan `BEFORE DELETE`) sehingga jejak audit tidak dapat diubah maupun dihapus oleh siapa pun, termasuk Administrator ([src/database/models.py](../src/database/models.py)).

---

## BAB II. PROFIL MITRA DAN LINGKUNGAN SERVER IMPLEMENTASI

### 2.1 Instansi Mitra Implementasi
- **Nama Instansi Mitra** : **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan**
- **Lokasi Mitra** : Kabupaten Tabanan, Provinsi Bali
- **Objek Penerapan** : Pengamanan, verifikasi keaslian (*integrity check*), enkripsi arsip digital (`.seal`), dan pencatatan jejak audit pengelolaan dokumen administrasi haji dan umrah.

### 2.2 Arsitektur Server & Lingkungan Deployment (*On-Premise Local Server*)
Sesuai dengan kebijakan kerahasiaan dokumen instansi pemerintahan, sistem **DocSeal** diimplementasikan menggunakan model **Local On-Premise Server** (bukan *public cloud* pihak ketiga) agar seluruh dokumen fisik dan basis data tetap berada sepenuhnya di bawah kendali internal kantor mitra:
- **Model Deployment** : *On-Premise Localhost / Intranet Server* (`http://127.0.0.1:5000`) menggunakan *One-Click Launcher* ([Start_DocSeal.bat](../Start_DocSeal.bat) untuk Windows dan [start_docseal.sh](../start_docseal.sh) untuk Linux).
- **Penyimpanan Data Lokal** :
  - Basis Data Utama: SQLite3 pada `data/docseal.db` (memuat tabel `users`, `documents`, dan `audit_logs`).
  - Penyimpanan Dokumen & Sertifikat Verifikasi: `data/dummy_docs/`.
  - Penyimpanan Arsip Terenkripsi AES-256-GCM: `data/encrypted/*.seal`.
- **Pembagian Peran Pengguna di Mitra (RBAC)**:
  1. **Admin (`admin`)**: Mengelola akun pegawai, memantau sistem, dan mengunduh **Backup Sistem Lengkap (`.ZIP`)**.
  2. **Operator (`operator`)**: Mengunggah/meregistrasi dokumen baru maupun revisi, serta melakukan enkripsi dan dekripsi arsip `.seal`.
  3. **Staf Pelayanan (`staf`)**: Memverifikasi keaslian dokumen dan mencetak **Berita Acara Verifikasi (PDF)** berkop instansi.
  4. **Auditor / Pengawas (`auditor`)**: Menjalankan **Batch Integrity Scan** dan mengekspor laporan **Audit Trail (`.CSV`)**.

---

## BAB III. PROGRES IMPLEMENTASI PROYEK

Secara keseluruhan, progres pengembangan perangkat lunak, pengerasan keamanan (*security hardening*), dan pengujian sistem telah mencapai **100% (Siap Pakai di Mitra)**, dengan rincian tahapan sebagai berikut:

### 3.1 Tabel Rekapitulasi Progres Modul

| No | Modul / Tahapan Kerja | Deskripsi Implementasi Teknis | Status | Capaian |
| :-: | :--- | :--- | :---: | :---: |
| **1** | **Perancangan Basis Data & Immutable Trigger** | Pembuatan skema tabel `users`, `documents`, dan `audit_logs` beserta trigger `prevent_audit_log_update` & `prevent_audit_log_delete` di SQLite3. | **Selesai** | **100%** |
| **2** | **Mesin Integritas SHA-256 & Versioning** | Implementasi hashing SHA-256 per 4KB chunk, deteksi duplikat identik (`DUPLICATE`), *auto-versioning* (`v1`, `v2`), dan *Batch Integrity Scan*. | **Selesai** | **100%** |
| **3** | **Mesin Kriptografi AES-256-GCM (`.seal`)** | Implementasi enkripsi dan dekripsi dokumen menggunakan AES-256-GCM + PBKDF2-HMAC-SHA256 (100.000 iterasi) serta validasi *Authentication Tag*. | **Selesai** | **100%** |
| **4** | **RBAC 4 Peran & Proteksi Kredensial** | Autentikasi PBKDF2 + Salt, proteksi *Timing Attack* (`hmac.compare_digest`), *Brute-Force Lockout* (5x gagal login), manajemen user, & ganti password mandiri. | **Selesai** | **100%** |
| **5** | **Antarmuka Web UI Lokal & CLI** | Pembuatan Dashboard Web UI (Flask offline-ready) beridentitas resmi mitra, antarmuka CLI lengkap (`argparse`), serta *launcher* satu klik (`.bat` & `.sh`). | **Selesai** | **100%** |
| **6** | **Fitur Operasional Mitra (Sertifikat PDF & Backup)** | Fitur cetak **Berita Acara Verifikasi Keaslian (PDF)** berkop Kemenhaj Tabanan, ekspor laporan Audit Trail (`.CSV`), dan **Backup Sistem (`.ZIP`)**. | **Selesai** | **100%** |
| **7** | **Security Hardening & Validasi Input** | Validasi *magic bytes* header PDF (`%PDF-`), pembatasan ukuran file maksimal 10 MB (anti-DoS), sanitasi anti-*Path Traversal*, dan 100% *SQL Parameterization* (`?`). | **Selesai** | **100%** |
| **8** | **Pengujian Otomatis & Audit SAST** | Pengujian unit/integrasi menggunakan `pytest` (9/9 skenario lulus), pemeriksaan kualitas kode `ruff` (0 error), dan pemindaian keamanan `bandit` (0 celah kerentanan). | **Selesai** | **100%** |
| **9** | **Penyiapan Dokumen Serah Terima & UAT Mitra** | Penyusunan template **Berita Acara Serah Terima (BAST)**, lembar **Form UAT**, dan **SOP Penggunaan Pegawai** untuk pelaksanaan sosialisasi & foto bersama di mitra. | **Selesai** | **100%** |

### 3.2 Hasil Pengujian Keamanan dan Fungsionalitas
1. **Functional & Security Unit Testing (`pytest -v`)**:
   - Seluruh **9 rangkaian pengujian otomatis lulus 100% (`9 passed`)**, mencakup siklus hidup SHA-256, enkripsi/dekripsi AES-256-GCM, penolakan *passphrase* salah, pembatasan akses RBAC, *immutable audit trigger*, *brute-force lockout*, penolakan file non-PDF, pencegahan *Path Traversal*, pencetakan Berita Acara PDF, dan Backup `.ZIP`.
2. **Static Application Security Testing (`bandit -r src/` & `ruff check`)**:
   - Pemindaian terhadap **1.179 baris kode sumber** menghasilkan **0 temuan kerentanan** (*High: 0, Medium: 0, Low: 0*) dan **0 peringatan linter**.

### 3.3 Rencana Tahap Akhir (Pelaksanaan di Lokasi Mitra)
Dengan selesainya 100% pengembangan aplikasi dan paket dokumen uji di [docs/DOKUMEN_SERAH_TERIMA_MITRA.md](DOKUMEN_SERAH_TERIMA_MITRA.md), agenda terakhir yang siap dilaksanakan bersama mitra **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan** adalah:
1. Instalasi dan demonstrasi langsung aplikasi **DocSeal** pada perangkat komputer operasional mitra.
2. Pengujian penerimaan pengguna (*User Acceptance Test* / UAT) bersama pegawai mitra beserta penandatanganan Berita Acara Implementasi.
3. Pengambilan dokumentasi foto bersama dan penyerahan SOP operasional sistem.

# Paket Dokumen Serah Terima, UAT, & Panduan Dokumentasi Mitra
**Instansi Mitra**: Kantor Kementerian Haji dan Umrah Kabupaten Tabanan  
**Nama Sistem**: **DocSeal** (*Sistem Perlindungan, Verifikasi Integritas SHA-256, Enkripsi AES-256-GCM, & Audit Trail Dokumen Digital On-Premise*)

---

## 1. Panduan Sesi Foto Dokumentasi di Kantor Mitra (Wajib untuk Laporan Dosen)

Agar dokumentasi diterima penuh oleh dosen pengampu mata kuliah **Applied Cyber Security**, ambil **4 foto** berikut saat berkunjung ke Kantor Kementerian Haji dan Umrah Kabupaten Tabanan:

1. **Foto 1 — Foto Bersama Resmi (Plang / Ruang Layanan Instansi)**
   - **Objek**: Anda bersama perwakilan pejabat/staf mitra berdiri di depan papan nama atau ruang pelayanan Kantor Kementerian Haji dan Umrah Kabupaten Tabanan.
   - **Properti yang Dipegang**: Map berisi **Berita Acara Serah Terima (BAST)** dan hasil cetak **Berita Acara Verifikasi Integritas Dokumen (PDF)** dari DocSeal.
2. **Foto 2 — Foto Demonstrasi & Sosialisasi Aplikasi di Komputer Mitra**
   - **Objek**: Layar laptop/PC kantor menampilkan **Dashboard Web UI DocSeal** (terlihat judul *Kantor Kementerian Haji dan Umrah Kabupaten Tabanan* dan kotak hijau *Hasil Verifikasi SHA-256: VALID*), dengan pegawai mitra sedang mengoperasikan atau memperhatikan layar bersama Anda.
3. **Foto 3 — Foto Pengujian Fitur Keamanan (UAT oleh Pegawai Mitra)**
   - **Objek**: Pegawai mitra sedang mencoba fitur **Buat PDF Dummy / Upload Dokumen**, **Enkripsi AES-256 (`.seal`)**, atau **Cetak Berita Acara Verifikasi PDF**.
4. **Foto 4 — Foto Penandatanganan BAST & Form UAT**
   - **Objek**: Perwakilan mitra sedang menandatangani dan memberi stempel pada lembar **Berita Acara Implementasi** dan **Form UAT**.

---

## 2. Template Berita Acara Implementasi & Uji Coba Sistem (Siap Cetak)

> *Salin bagian di bawah ini ke Microsoft Word / Google Docs, cetak 2 rangkap, dan mintakan tanda tangan serta stempel basah di Kantor Mitra.*

---

### BERITA ACARA IMPLEMENTASI DAN UJI COBA SISTEM KEAMANAN DOKUMEN DIGITAL (DOCSEAL)

Pada hari ini, **....................**, tanggal **......** bulan **....................** tahun **2026**, bertempat di **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan**, telah dilaksanakan kegiatan demonstrasi, instalasi lokal (*on-premise*), dan pengujian fungsionalitas keamanan sistem:

- **Nama Sistem**: **DocSeal** (*Digital Document Protection & Integrity Verification Tool*)
- **Ruang Lingkup Keamanan**:
  1. Pemeriksaan keaslian & integritas dokumen menggunakan algoritma *cryptographic hashing* **SHA-256**, anti-duplikasi, dan *auto-versioning*.
  2. Perlindungan kerahasiaan arsip sensitif menggunakan enkripsi **AES-256-GCM** (`.seal`) dengan derivasi kunci **PBKDF2-HMAC-SHA256**.
  3. Pembatasan hak akses pengguna berbasis peran (**RBAC**: *Admin, Operator, Staf, Auditor*) serta proteksi *Brute-Force Lockout*.
  4. Pencatatan jejak aktivitas pengguna secara otomatis dan permanen (*Immutable Audit Trail*) beserta fitur pencetakan **Berita Acara Verifikasi PDF** dan **Backup Sistem (.ZIP)**.

Berdasarkan hasil uji coba (*User Acceptance Test* terlampir), sistem **DocSeal** dinyatakan telah berjalan dengan baik secara lokal (*offline/on-premise*) dan sesuai dengan kebutuhan pengamanan serta verifikasi keaslian dokumen digital pada lingkungan **Kantor Kementerian Haji dan Umrah Kabupaten Tabanan**.

Demikian Berita Acara ini dibuat dengan sebenarnya untuk dapat dipergunakan sebagaimana mestinya.

Tabanan, ...... .................... 2026

| Pihak Mitra Instansi<br>**Kantor Kementerian Haji dan Umrah Kab. Tabanan** | Pengembang Sistem<br>**Mahasiswa Pelaksana Proyek** |
| :---: | :---: |
| <br><br><br><br>**( .................................................... )**<br>NIP. .................................................... | <br><br><br><br>**( .................................................... )**<br>NIM. .................................................... |

---

## 3. Lembar Pengujian Pengguna / *User Acceptance Test* (UAT)

**Nama Penguji (Perwakilan Mitra)**: ............................................................  
**Jabatan / Peran Uji**: ............................................................  
**Tanggal Pengujian**: ............................................................

| No | Modul / Fitur Keamanan | Skenario Pengujian di Mitra | Hasil yang Diharapkan | Status Uji |
| :-: | :--- | :--- | :--- | :---: |
| **1** | **Autentikasi & RBAC** | Login menggunakan akun `admin`, `operator`, `staf`, dan `auditor` serta uji proteksi salah password 5x. | Sistem membatasi menu sesuai peran dan mengunci akun sementara saat gagal login 5x beruntun. | [ ] Sesuai<br>[ ] Tidak |
| **2** | **Generator PDF & Validasi Input** | Membuat PDF uji melalui menu **Buat PDF Dummy Kustom** dan mengunggah file non-PDF. | PDF berhasil dibuat dengan kop instansi; file palsu/non-PDF (`%PDF-`) otomatis ditolak. | [ ] Sesuai<br>[ ] Tidak |
| **3** | **Registrasi SHA-256 & Anti-Duplikat** | Mengunggah berkas PDF pertama kali (`v1`), lalu mengunggah berkas yang 100% identik kedua kalinya. | Berkas pertama terdaftar (`v1`), berkas identik ditolak (`DUPLICATE`), berkas revisi naik ke `v2`. | [ ] Sesuai<br>[ ] Tidak |
| **4** | **Verifikasi Integritas & Berita Acara PDF** | Memeriksa file asli (`VALID`) dan file yang diubah isinya (`MODIFIED`), lalu klik **Cetak Berita Acara Verifikasi (PDF)**. | Sistem mendeteksi perubahan bit secara akurat dan mengunduh PDF Berita Acara Verifikasi resmi. | [ ] Sesuai<br>[ ] Tidak |
| **5** | **Batch Integrity Scan** | Menekan tombol **Pindai Seluruh Arsip Lokal (Batch Scan)** pada Dashboard. | Sistem memeriksa keutuhan seluruh dokumen terdaftar di media penyimpanan sekaligus. | [ ] Sesuai<br>[ ] Tidak |
| **6** | **Enkripsi & Dekripsi AES-256-GCM** | Mengunci dokumen menjadi `.seal` dengan passphrase, lalu mendekripsinya kembali dengan passphrase yang benar dan salah. | File `.seal` tidak dapat dibuka tanpa passphrase yang sah; passphrase salah langsung ditolak. | [ ] Sesuai<br>[ ] Tidak |
| **7** | **Ganti Password & Manajemen User** | Menambahkan akun pegawai baru oleh Admin dan mengganti password akun melalui menu **Keamanan Akun**. | Akun baru terdaftar dan password baru langsung aktif dengan hashing PBKDF2-SHA256. | [ ] Sesuai<br>[ ] Tidak |
| **8** | **Immutable Audit Trail & Backup (.ZIP)** | Mengekspor laporan **Audit Trail (.CSV)** dan mengunduh **Backup Sistem (.ZIP)**. | Seluruh aktivitas tercatat lengkap (tidak dapat dihapus) dan terunduh dalam format `.csv` & `.zip`. | [ ] Sesuai<br>[ ] Tidak |

**Catatan / Masukan Mitra**:  
....................................................................................................................................................................................  
....................................................................................................................................................................................

**Tanda Tangan Penguji Mitra**:  
<br><br>
**( .................................................... )**

---

## 4. SOP Singkat Penggunaan DocSeal untuk Pegawai Mitra (1 Halaman)

1. **Menjalankan Aplikasi**:
   - Pengguna Windows: Klik 2x file **`Start_DocSeal.bat`**.
   - Pengguna Linux: Jalankan **`./start_docseal.sh`**.
   - Browser otomatis terbuka ke alamat lokal `http://127.0.0.1:5000`.
2. **Pembagian Akun Operasional (RBAC)**:
   - **Admin** (`admin`): Mengelola akun pegawai, mengunduh **Backup Sistem (.ZIP)**, dan akses penuh.
   - **Operator** (`operator`): Membuat PDF simulasi, mengunggah dokumen baru/revisi, serta mengenkripsi/mendekripsi arsip `.seal`.
   - **Staf Pelayanan** (`staf`): Memverifikasi keaslian dokumen jamaah dan mencetak **Berita Acara Verifikasi (PDF)**.
   - **Auditor / Pengawas** (`auditor`): Memeriksa keaslian seluruh arsip (**Batch Scan**) dan mengunduh laporan **Audit Trail (.CSV)**.
3. **Prosedur Rutin Backup Keamanan**:
   - Setiap akhir pekan, Admin disarankan menekan tombol **Backup Sistem (.ZIP)** di pojok kanan atas Dashboard dan menyimpan file `DocSeal_System_Backup.zip` ke media penyimpanan cadangan kantor.


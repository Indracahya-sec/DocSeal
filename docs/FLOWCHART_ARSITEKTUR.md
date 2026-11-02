# Flowchart Interaktif Arsitektur & Kode DocSeal

> [!TIP]
> **Klik langsung pada kotak (node) di dalam diagram Mermaid** atau pada **tautan fungsi di tabel indeks** di bawah setiap diagram untuk langsung melompat ke file dan baris kode aslinya di editor.

---

## 1. Peta Arsitektur Utama (End-to-End Overview)

```mermaid
flowchart TD
    subgraph UI["Layer Antarmuka (Dual Interface)"]
        MAIN["main.py (Web Server Starter)"]
        WEB["src/web/app.py (Flask Local Web UI)"]
        CLI["src/cli/main_cli.py (Terminal CLI)"]
        DUMMY["tests/generate_dummy.py (Custom PDF Generator)"]
    end

    subgraph CORE["Layer Keamanan Inti (src/core/)"]
        RBAC["rbac.py (Auth, 4 Role, Brute-Force Lockout)"]
        HASHER["hasher.py (SHA-256 4KB, Deduplikasi, Versioning, Scan)"]
        CRYPTO["crypto.py (AES-256-GCM + PBKDF2 .seal)"]
        AUDIT["audit.py (Audit Trail Logger & CSV Export)"]
    end

    subgraph DATA["Layer Penyimpanan & Database Lokal"]
        CFG["src/config.py (Path & Secret Key)"]
        CONN["connection.py (Context Manager db_session)"]
        MOD["models.py (Skema SQL + Trigger Immutable)"]
        SEED["seed.py (4 Akun Default RBAC)"]
    end

    MAIN --> SEED
    MAIN --> WEB
    WEB --> DUMMY
    CLI --> DUMMY

    WEB --> RBAC
    CLI --> RBAC
    WEB --> HASHER
    CLI --> HASHER
    WEB --> CRYPTO
    CLI --> CRYPTO
    WEB --> AUDIT
    CLI --> AUDIT

    RBAC --> AUDIT
    HASHER --> AUDIT
    CRYPTO --> AUDIT

    RBAC --> CONN
    HASHER --> CONN
    CRYPTO --> CONN
    AUDIT --> CONN
    SEED --> MOD
    MOD --> CONN
    CONN --> CFG

    click MAIN "../main.py#L1-L7" "Buka main.py"
    click WEB "../src/web/app.py#L20-L311" "Buka app.py"
    click CLI "../src/cli/main_cli.py#L85-L216" "Buka main_cli.py"
    click DUMMY "../tests/generate_dummy.py#L26-L70" "Buka generate_dummy.py"
    click RBAC "../src/core/rbac.py#L8-L137" "Buka rbac.py"
    click HASHER "../src/core/hasher.py#L9-L149" "Buka hasher.py"
    click CRYPTO "../src/core/crypto.py#L19-L112" "Buka crypto.py"
    click AUDIT "../src/core/audit.py#L7-L68" "Buka audit.py"
    click CFG "../src/config.py#L3-L15" "Buka config.py"
    click CONN "../src/database/connection.py#L7-L24" "Buka connection.py"
    click MOD "../src/database/models.py#L3-L53" "Buka models.py"
    click SEED "../src/database/seed.py#L13-L27" "Buka seed.py"
```

| Komponen Arsitektur | Lompat ke Kode Sumber |
| :--- | :--- |
| Entry Point & Seeding Awal | [main.py](../main.py#L1-L7) · [`seed_database()`](../src/database/seed.py#L13-L27) · [`init_db()`](../src/database/models.py#L50-L53) |
| Konfigurasi & Sesi SQLite | [config.py](../src/config.py#L3-L15) · [`db_session()`](../src/database/connection.py#L17-L24) |
| Antarmuka Pengguna (Web & CLI) | [app.py](../src/web/app.py#L122-L311) · [main_cli.py](../src/cli/main_cli.py#L85-L216) · [`create_custom_pdf()`](../tests/generate_dummy.py#L26-L70) |

---

## 2. Alur Autentikasi, Proteksi Brute-Force, & Otorisasi RBAC

```mermaid
flowchart TD
    L1["Input Kredensial: Web login() / CLI require_auth_and_perm()"] --> L2["authenticate_user(username, password)"]
    L2 --> L3{"is_account_locked()? (≥ 5x Gagal dlm 15 Menit)"}
    L3 -- "Ya (Terkunci)" --> L4["log_action: LOCKED_BRUTEFORCE & Tolak Login"]
    L3 -- "Tidak" --> L5{"verify_password()? (PBKDF2 + hmac.compare_digest)"}
    L5 -- "Salah" --> L6["log_action: LOGIN FAILED"]
    L5 -- "Cocok" --> L7["log_action: LOGIN SUCCESS"]
    L7 --> L8{"Cek Izin Aksi: has_permission() / @require_perm"}
    L8 -- "Tidak Diizinkan" --> L9["log_action: ACCESS_DENIED & Blokir Aksi"]
    L8 -- "Diizinkan" --> L10["Eksekusi Fitur Sesuai Role"]

    click L1 "../src/web/app.py#L122-L137" "Buka login() di app.py"
    click L2 "../src/core/rbac.py#L60-L81" "Buka authenticate_user()"
    click L3 "../src/core/rbac.py#L38-L57" "Buka is_account_locked()"
    click L4 "../src/core/rbac.py#L67-L74" "Buka log LOCKED_BRUTEFORCE"
    click L5 "../src/core/rbac.py#L25-L30" "Buka verify_password()"
    click L6 "../src/core/rbac.py#L80-L81" "Buka log LOGIN FAILED"
    click L7 "../src/core/rbac.py#L76-L78" "Buka log LOGIN SUCCESS"
    click L8 "../src/web/app.py#L32-L50" "Buka decorator require_perm()"
    click L9 "../src/cli/main_cli.py#L24-L32" "Buka blokir RBAC di CLI"
    click L10 "../src/core/rbac.py#L8-L13" "Buka ROLE_PERMISSIONS"
```

| Tahap Eksekusi | Lompat ke Baris Kode |
| :--- | :--- |
| Matriks 4 Role (`ROLE_PERMISSIONS`) | [`ROLE_PERMISSIONS`](../src/core/rbac.py#L8-L13) · [`has_permission()`](../src/core/rbac.py#L33-L35) |
| Hashing & Anti-Timing Attack | [`hash_password()`](../src/core/rbac.py#L18-L22) · [`verify_password()`](../src/core/rbac.py#L25-L30) |
| Deteksi Brute-Force & Login | [`is_account_locked()`](../src/core/rbac.py#L38-L57) · [`authenticate_user()`](../src/core/rbac.py#L60-L81) |
| Guard RBAC di Web & CLI | [`require_perm()`](../src/web/app.py#L32-L50) · [`require_auth_and_perm()`](../src/cli/main_cli.py#L18-L34) |
| Manajemen Akun oleh Admin | [`create_user()`](../src/core/rbac.py#L95-L137) · [`create_user_route()`](../src/web/app.py#L288-L300) |

---

## 3. Alur Upload, SHA-256 Chunking, Deduplikasi, & Auto-Versioning

```mermaid
flowchart TD
    U1["Terima File: Web upload() / CLI _handle_upload()"] --> U2["_saved_temp_upload() (Isolasi File Sementara)"]
    U2 --> U3["calculate_sha256() (Baca Bertahap per 4096 Bytes)"]
    U3 --> U4{"Cek Tabel documents: sha256_hash Sudah Ada?"}
    U4 -- "Ya (100% Identik)" --> U5["log_action: DUPLICATE_REJECTED & Hapus File Temp"]
    U4 -- "Tidak (Konten Baru)" --> U6["Hitung Versi: COALESCE(MAX(version), 0) + 1"]
    U6 --> U7["Simpan ke Tabel documents & Rename Fisik _vN.pdf"]
    U7 --> U8["log_action: NEW_DOCUMENT (v1) / NEW_VERSION (v2+)"]

    click U1 "../src/web/app.py#L186-L206" "Buka upload() di app.py"
    click U2 "../src/web/app.py#L54-L62" "Buka _saved_temp_upload()"
    click U3 "../src/core/hasher.py#L9-L19" "Buka calculate_sha256()"
    click U4 "../src/core/hasher.py#L28-L31" "Buka cek duplikat SHA-256"
    click U5 "../src/core/hasher.py#L43-L55" "Buka penolakan duplikat"
    click U6 "../src/core/hasher.py#L34-L37" "Buka query auto-versioning"
    click U7 "../src/web/app.py#L198-L203" "Buka penamaan versi fisik"
    click U8 "../src/core/hasher.py#L57-L72" "Buka pencatatan dokumen baru"
```

| Tahap Eksekusi | Lompat ke Baris Kode |
| :--- | :--- |
| Mesin SHA-256 (4KB Chunking) | [`calculate_sha256()`](../src/core/hasher.py#L9-L19) |
| Deduplikasi & Auto-Versioning | [`register_document()`](../src/core/hasher.py#L22-L72) |
| Penanganan Upload Aman Web UI | [`_saved_temp_upload()`](../src/web/app.py#L54-L62) · [`upload()`](../src/web/app.py#L186-L206) |

---

## 4. Alur Verifikasi Integritas Satuan & Batch Integrity Scan

```mermaid
flowchart LR
    subgraph SINGLE["Verifikasi Satuan"]
        V1["Pilih doc_id & File Uji"] --> V2["verify_document_integrity()"]
        V2 --> V3{"Hash File == Hash DB?"}
        V3 -- "Sama" --> V4["Status: VALID"]
        V3 -- "Beda 1-bit+" --> V5["Status: MODIFIED"]
    end

    subgraph BATCH["Batch Scan Seluruh Arsip"]
        S1["Tombol Batch Scan / CLI scan"] --> S2["scan_all_documents_integrity()"]
        S2 --> S3["_inspect_doc_row() per Dokumen"]
        S3 --> S4["Rekap Counter: VALID / MODIFIED / MISSING"]
    end

    click V1 "../src/web/app.py#L211-L222" "Buka route verify()"
    click V2 "../src/core/hasher.py#L75-L103" "Buka verify_document_integrity()"
    click V3 "../src/core/hasher.py#L82-L85" "Buka perbandingan hash"
    click V4 "../src/core/hasher.py#L87-L93" "Buka log hasil verifikasi"
    click V5 "../src/core/hasher.py#L87-L93" "Buka log mismatch hash"
    click S1 "../src/web/app.py#L227-L228" "Buka scan_all_route()"
    click S2 "../src/core/hasher.py#L126-L149" "Buka scan_all_documents_integrity()"
    click S3 "../src/core/hasher.py#L106-L123" "Buka _inspect_doc_row()"
    click S4 "../src/core/hasher.py#L132-L149" "Buka agregasi status Batch Scan"
```

| Tahap Eksekusi | Lompat ke Baris Kode |
| :--- | :--- |
| Verifikasi Dokumen Satuan | [`verify_document_integrity()`](../src/core/hasher.py#L75-L103) · [`verify()`](../src/web/app.py#L211-L222) |
| Batch Scan Deteksi Disk Tampering | [`_inspect_doc_row()`](../src/core/hasher.py#L106-L123) · [`scan_all_documents_integrity()`](../src/core/hasher.py#L126-L149) |

---

## 5. Alur Enkripsi & Dekripsi AES-256-GCM (`.seal`) + Immutable Audit Log

```mermaid
flowchart TD
    subgraph ENC["Enkripsi Dokumen (.seal)"]
        C1["encrypt_document(doc_id, passphrase)"] --> C2["os.urandom: Salt (16B) + Nonce (12B)"]
        C2 --> C3["_derive_aes256_key() (PBKDF2 100.000 Iterasi)"]
        C3 --> C4["AESGCM.encrypt() -> Simpan Salt+Nonce+Ciphertext+Tag"]
    end

    subgraph DEC["Dekripsi Dokumen (.seal)"]
        D1["decrypt_document(seal_path, passphrase)"] --> D2["Pisahkan Header: Salt (16B) & Nonce (12B)"]
        D2 --> D3["_derive_aes256_key() & AESGCM.decrypt()"]
        D3 --> D4{"Validasi GCM Auth Tag"}
        D4 -- "InvalidTag (Kunci Salah / File Rusak)" --> D5["log_action: FAILED_INVALID_KEY & Raise ValueError"]
        D4 -- "Valid" --> D6["Tulis PDF Asli Utuh & log_action: DECRYPT SUCCESS"]
    end

    subgraph IMMUTABLE["Immutable Audit Trail (SQLite)"]
        A1["log_action() -> INSERT INTO audit_logs"] --> A2["SQLite Trigger: Blokir UPDATE & DELETE"]
        A1 --> A3["export_audit_logs_csv() (Laporan CSV Auditor)"]
    end

    C4 --> A1
    D5 --> A1
    D6 --> A1

    click C1 "../src/core/crypto.py#L29-L62" "Buka encrypt_document()"
    click C2 "../src/core/crypto.py#L41-L41" "Buka pembangkitan Salt & Nonce"
    click C3 "../src/core/crypto.py#L19-L26" "Buka _derive_aes256_key()"
    click C4 "../src/core/crypto.py#L42-L50" "Buka penyimpanan format biner .seal"
    click D1 "../src/core/crypto.py#L65-L112" "Buka decrypt_document()"
    click D2 "../src/core/crypto.py#L81-L85" "Buka ekstraksi header .seal"
    click D3 "../src/core/crypto.py#L87-L88" "Buka dekripsi AESGCM"
    click D4 "../src/core/crypto.py#L87-L97" "Buka penanganan InvalidTag"
    click D5 "../src/core/crypto.py#L89-L97" "Buka log FAILED_INVALID_KEY"
    click D6 "../src/core/crypto.py#L99-L112" "Buka penyimpanan hasil dekripsi"
    click A1 "../src/core/audit.py#L7-L19" "Buka log_action()"
    click A2 "../src/database/models.py#L36-L46" "Buka Trigger Immutable SQLite"
    click A3 "../src/core/audit.py#L22-L68" "Buka export_audit_logs_csv()"
```

| Tahap Eksekusi | Lompat ke Baris Kode |
| :--- | :--- |
| Derivasi Kunci PBKDF2-HMAC-SHA256 | [`_derive_aes256_key()`](../src/core/crypto.py#L19-L26) |
| Enkripsi & Unduh `.seal` | [`encrypt_document()`](../src/core/crypto.py#L29-L62) · [`encrypt_route()`](../src/web/app.py#L243-L257) · [`download_seal()`](../src/web/app.py#L305-L311) |
| Dekripsi & Verifikasi GCM Tag | [`decrypt_document()`](../src/core/crypto.py#L65-L112) · [`decrypt_route()`](../src/web/app.py#L262-L283) |
| Immutable Audit Log & CSV Export | [`log_action()`](../src/core/audit.py#L7-L19) · [`prevent_audit_log_update`](../src/database/models.py#L36-L46) · [`export_audit_logs_csv()`](../src/core/audit.py#L22-L68) |


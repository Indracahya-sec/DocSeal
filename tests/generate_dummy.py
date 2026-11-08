import argparse
import re
import shutil
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from src.config import DUMMY_DIR, ensure_directories, resolve_safe_path


def _safe_latin1(text: str) -> str:
    """Memastikan teks kompatibel dengan font standar Helvetica FPDF."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def sanitize_pdf_filename(name: str) -> str:
    """Membersihkan nama file dokumen dan memastikan ekstensi .pdf."""
    clean = Path(name.strip()).name
    clean = re.sub(r"[^\w\-. ]+", "_", clean).strip().replace(" ", "_")
    if not clean:
        clean = "Dokumen_Dummy"
    if not clean.lower().endswith(".pdf"):
        clean = f"{clean}.pdf"
    return clean


def create_custom_pdf(
    filename: str,
    content: str,
    title: str = "DOKUMEN SIMULASI PENGUJIAN (100% DATA DUMMY / FIKTIF)",
    output_dir: Path | None = None,
) -> Path:
    """Membuat berkas PDF dummy dengan nama file dan isi teks kustom."""
    ensure_directories()
    target_dir = output_dir if output_dir is not None else DUMMY_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_filename = sanitize_pdf_filename(filename)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(
        0,
        10,
        "KEMENTERIAN HAJI DAN UMRAH - KABUPATEN TABANAN",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
        align="C",
    )
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(
        0,
        8,
        _safe_latin1(title),
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
        align="C",
    )
    pdf.ln(6)

    pdf.set_font("Helvetica", "", 12)
    normalized_content = content.replace("\\n", "\n").strip()
    if not normalized_content:
        normalized_content = "Dokumen simulasi pengujian DocSeal (100% Data Dummy)."

    pdf.multi_cell(0, 8, _safe_latin1(normalized_content))

    output_path = resolve_safe_path(safe_filename, target_dir=target_dir, root_dir=target_dir)
    pdf.output(str(output_path))
    print(f"[+] Berhasil membuat PDF Dummy: {output_path}")
    return output_path


def create_pdf(filename: str, nama: str, nik: str, porsi: str, alamat: str) -> Path:
    """Membuat 1 file PDF dokumen jamaah fiktif terstruktur (100% Data Dummy)."""
    body = (
        f"Nama Jamaah   : {nama}\n"
        f"NIK (Dummy)   : {nik}\n"
        f"Nomor Porsi   : {porsi}\n"
        f"Alamat        : {alamat}"
    )
    return create_custom_pdf(filename=filename, content=body)


def generate_all_dummies() -> None:
    """Membangkitkan 3 paket PDF dummy standar (Asli, Duplikat Identik, dan Revisi)."""
    ensure_directories()

    # 1. File Asli (Versi 1)
    orig_path = create_pdf(
        filename="Berkas_Jamaah_01.pdf",
        nama="I Made Dummy Simulasi",
        nik="5102010000000001",
        porsi="5100099901",
        alamat="Jl. Pahlawan No. 10, Tabanan",
    )

    # 2. File Duplikat Identik 100% (Salinan byte-for-byte untuk tes Deduplikasi)
    copy_path = DUMMY_DIR / "Berkas_Jamaah_01_Copy.pdf"
    shutil.copyfile(orig_path, copy_path)
    print(f"[+] Berhasil membuat Duplikat Identik: {copy_path}")

    # 3. File Revisi / Terubah (Beda alamat untuk tes Auto-Versioning & Tamper Detection)
    create_pdf(
        filename="Berkas_Jamaah_01_Revisi.pdf",
        nama="I Made Dummy Simulasi",
        nik="5102010000000001",
        porsi="5100099901",
        alamat="Jl. Diponegoro No. 99, Kediri, Tabanan (REVISI)",
    )


def interactive_prompt() -> None:
    """Mode interaktif di terminal untuk memasukkan nama dokumen dan isinya secara bebas."""
    print("\n=== GENERATOR DOKUMEN PDF DUMMY KUSTOM (DOCSEAL) ===")
    doc_name = input("1. Masukkan nama dokumen (contoh: Berkas_Jamaah_02): ").strip()
    if not doc_name:
        doc_name = "Dokumen_Dummy_Baru"

    custom_title = input(
        "2. Subjudul dokumen [Enter untuk default simulasi]: "
    ).strip()

    print("3. Masukkan isi dokumen (bisa beberapa baris, tekan Enter pada baris kosong jika selesai):")
    lines: list[str] = []
    while True:
        line = input("   > ")
        if line == "":
            if lines:
                break
            print("   [!] Isi belum dimasukkan. Ketik minimal 1 baris teks:")
            continue
        lines.append(line)

    content_text = "\n".join(lines)
    kwargs = {"filename": doc_name, "content": content_text}
    if custom_title:
        kwargs["title"] = custom_title

    created_path = create_custom_pdf(**kwargs)

    make_copy = input(
        "4. Buat juga salinan identik (_Copy.pdf) untuk uji anti-duplikat? (y/N): "
    ).strip().lower()
    if make_copy == "y":
        copy_path = DUMMY_DIR / f"{created_path.stem}_Copy.pdf"
        shutil.copyfile(created_path, copy_path)
        print(f"[+] Berhasil membuat salinan identik: {copy_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generator PDF Data Dummy DocSeal (Interaktif & Argumen CLI)"
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Nama dokumen PDF yang ingin dibuat (contoh: Surat_Pengantar_01)",
    )
    parser.add_argument(
        "-i",
        "--isi",
        "--content",
        dest="content",
        help="Isi teks di dalam dokumen PDF (gunakan \\n untuk baris baru)",
    )
    parser.add_argument(
        "-t",
        "--title",
        default="DOKUMEN SIMULASI PENGUJIAN (100% DATA DUMMY / FIKTIF)",
        help="Subjudul header di dalam PDF",
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="Sekaligus buat salinan identik (<nama>_Copy.pdf) untuk tes deduplikasi",
    )
    parser.add_argument(
        "--default",
        action="store_true",
        help="Bangkitkan 3 file PDF dummy standar otomatis tanpa input interaktif",
    )

    args = parser.parse_args()

    if args.default:
        generate_all_dummies()
        return

    if args.name or args.content:
        doc_name = args.name or "Dokumen_Dummy_Kustom"
        doc_content = args.content or "Dokumen simulasi pengujian DocSeal (100% Data Dummy)."
        out = create_custom_pdf(filename=doc_name, content=doc_content, title=args.title)
        if args.copy:
            copy_path = DUMMY_DIR / f"{out.stem}_Copy.pdf"
            shutil.copyfile(out, copy_path)
            print(f"[+] Berhasil membuat salinan identik: {copy_path}")
        return

    interactive_prompt()


if __name__ == "__main__":
    main()

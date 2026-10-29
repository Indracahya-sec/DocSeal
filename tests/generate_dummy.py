import shutil
from fpdf import FPDF
from src.config import DUMMY_DIR, ensure_directories


def create_pdf(filename: str, nama: str, nik: str, porsi: str, alamat: str) -> None:
    """Membuat 1 file PDF dokumen jamaah fiktif (100% Data Dummy)."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(
        0, 10, "KEMENTERIAN HAJI DAN UMRAH - KABUPATEN TABANAN", ln=True, align="C"
    )
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(
        0,
        8,
        "DOKUMEN SIMULASI PENGUJIAN (100% DATA DUMMY / FIKTIF)",
        ln=True,
        align="C",
    )
    pdf.ln(8)

    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, f"Nama Jamaah   : {nama}", ln=True)
    pdf.cell(0, 8, f"NIK (Dummy)   : {nik}", ln=True)
    pdf.cell(0, 8, f"Nomor Porsi   : {porsi}", ln=True)
    pdf.cell(0, 8, f"Alamat        : {alamat}", ln=True)

    output_path = DUMMY_DIR / filename
    pdf.output(str(output_path))
    print(f"[+] Berhasil membuat PDF Dummy: {output_path.name}")


def generate_all_dummies() -> None:
    ensure_directories()

    # 1. File Asli (Versi 1)
    create_pdf(
        filename="Berkas_Jamaah_01.pdf",
        nama="I Made Dummy Simulasi",
        nik="5102010000000001",
        porsi="5100099901",
        alamat="Jl. Pahlawan No. 10, Tabanan",
    )

    # 2. File Duplikat Identik 100% (Salinan byte-for-byte untuk tes Deduplikasi)
    shutil.copyfile(
        DUMMY_DIR / "Berkas_Jamaah_01.pdf", DUMMY_DIR / "Berkas_Jamaah_01_Copy.pdf"
    )
    print("[+] Berhasil membuat Duplikat Identik: Berkas_Jamaah_01_Copy.pdf")

    # 3. File Revisi / Terubah (Beda alamat untuk tes Auto-Versioning & Tamper Detection)
    create_pdf(
        filename="Berkas_Jamaah_01_Revisi.pdf",
        nama="I Made Dummy Simulasi",
        nik="5102010000000001",
        porsi="5100099901",
        alamat="Jl. Diponegoro No. 99, Kediri, Tabanan (REVISI)",
    )


if __name__ == "__main__":
    generate_all_dummies()

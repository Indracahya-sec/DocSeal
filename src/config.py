import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DUMMY_DIR = DATA_DIR / "dummy_docs"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
DB_PATH = DATA_DIR / "docseal.db"

SECRET_KEY = os.environ.get("DOCSEAL_SECRET_KEY") or secrets.token_hex(32)
MAX_FILE_SIZE = 10 * 1024 * 1024
PDF_MAGIC_HEADER = b"%PDF-"


def ensure_directories() -> None:
    """Memastikan direktori penyimpanan arsip lokal tersedia sebelum operasi I/O."""
    for directory in (DUMMY_DIR, ENCRYPTED_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def resolve_safe_path(
    filename: str | Path,
    target_dir: Path | None = None,
    root_dir: Path | None = None,
) -> Path:
    """Mencegah serangan Path Traversal dengan mengisolasi nama file di dalam direktori data/."""
    raw = str(filename).strip().replace("\\", "/")
    safe_name = Path(raw).name
    if not safe_name or safe_name in {".", ".."} or "/" in raw and Path(raw).stem in {"..", "."}:
        raise ValueError("Nama berkas tidak valid atau terdeteksi upaya Path Traversal.")

    base = (target_dir or DUMMY_DIR).resolve()
    allowed_root = (root_dir or DATA_DIR).resolve()
    resolved = (base / safe_name).resolve()

    if not resolved.is_relative_to(allowed_root):
        raise ValueError("Akses path di luar direktori data/ ditolak.")
    return resolved

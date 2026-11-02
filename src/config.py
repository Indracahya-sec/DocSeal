from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DUMMY_DIR = DATA_DIR / "dummy_docs"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
DB_PATH = DATA_DIR / "docseal.db"

SECRET_KEY = "docseal-local-onpremise-secret-key"


def ensure_directories() -> None:
    """Memastikan seluruh folder penyimpanan lokal tersedia."""
    for directory in (DUMMY_DIR, ENCRYPTED_DIR):
        directory.mkdir(parents=True, exist_ok=True)

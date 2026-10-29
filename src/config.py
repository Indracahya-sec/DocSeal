from pathlib import Path

# Menentukan root folder proyek (~/Desktop/DocSeal)
BASE_DIR = Path(__file__).resolve().parent.parent

# Lokasi folder data & sub-folder
DATA_DIR = BASE_DIR / "data"
DUMMY_DIR = DATA_DIR / "dummy_docs"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
DB_PATH = DATA_DIR / "docseal.db"

# Kunci rahasia untuk session Flask
SECRET_KEY = "docseal-local-onpremise-secret-key"

def ensure_directories() -> None:
    """Memastikan seluruh folder penyimpanan lokal tersedia."""
    DUMMY_DIR.mkdir(parents=True, exist_ok=True)
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

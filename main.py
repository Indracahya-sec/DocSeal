from src.database.seed import seed_database
from src.web.app import app

if __name__ == "__main__":
    seed_database()
    print("\n[+] Server Web UI Lokal DocSeal berjalan di: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)

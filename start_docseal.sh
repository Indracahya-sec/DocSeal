#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "==============================================================="
echo "  DOCSEAL - SISTEM KEAMANAN DAN INTEGRITAS DOKUMEN ON-PREMISE"
echo "  Kantor Kementerian Haji dan Umrah Kabupaten Tabanan"
echo "==============================================================="

if [ -x "./venv/bin/python" ]; then
    PYTHON_BIN="./venv/bin/python"
else
    PYTHON_BIN="python3"
fi

echo "[1/2] Memeriksa inisialisasi database lokal..."
"$PYTHON_BIN" -m src.database.seed

echo "[2/2] Menjalankan server lokal DocSeal di http://127.0.0.1:5000 ..."
"$PYTHON_BIN" -m src.web.app

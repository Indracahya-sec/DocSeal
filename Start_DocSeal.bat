@echo off
title DocSeal - Kantor Kementerian Haji dan Umrah Kab. Tabanan
echo ===============================================================
echo   DOCSEAL - SISTEM KEAMANAN DAN INTEGRITAS DOKUMEN ON-PREMISE
echo   Kantor Kementerian Haji dan Umrah Kabupaten Tabanan
echo ===============================================================
echo.
if exist venv\Scripts\python.exe (
    set PYTHON_BIN=venv\Scripts\python.exe
) else (
    set PYTHON_BIN=python
)
echo [1/2] Memeriksa inisialisasi database lokal...
%PYTHON_BIN% -m src.database.seed
echo.
echo [2/2] Menjalankan server lokal DocSeal pada http://127.0.0.1:5000 ...
start http://127.0.0.1:5000
%PYTHON_BIN% -m src.web.app
pause

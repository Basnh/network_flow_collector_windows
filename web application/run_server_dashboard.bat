@echo off
echo ========================================================
echo KHOI DONG NETWORK SECURITY MANAGEMENT SERVER
echo ========================================================

:: Chuyen huong lam viec hien tai ve thu muc chua file bat nay
cd /d "%~dp0"

echo.
echo Dang kiem tra Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [Loi] Khong tim thay Python. Vui long cai dat Python va them vao PATH system.
    pause
    exit /b
)

echo.
echo Dang khoi dong Server...
echo (Neu chua cai dat thu vien, vui long chay file install_modules.bat truoc)
echo.

python setup_and_run.py server

echo.
pause
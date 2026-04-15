@echo off
echo ========================================================
echo DANG CAI DAT CAC THU VIEN TU MODULE_REQUIREMENTS.TXT
echo ========================================================

:: Chuyen huong lam viec hien tai ve thu muc chua file bat nay
cd /d "%~dp0"

echo.
echo Dang kiem tra Python va pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [Loi] Khong tim thay Python hoac pip. Vui long cai dat Python va them vao PATH system.
    pause
    exit /b
)

echo.
echo Bat dau tai va cai dat...
python -m pip install -r module_requirements.txt

echo.
echo ========================================================
echo CAI DAT HOAN TAT!
echo ========================================================
pause

@echo off
echo ========================================================
echo THIET LAP DIA CHI LIEN KET DEN SERVER (DASHBOARD)
echo ========================================================
set /p SERVER_IP="Nhap dia chi IP cua Server (Nhan Enter de chay localhost): "
if "%SERVER_IP%"=="" set SERVER_IP=localhost
set SERVER_URL=http://%SERVER_IP%:5000

echo.
echo Dang yeu cau quyen Administrator de khoi dong Agent...
echo Se gui du lieu bao mat ve: %SERVER_URL%

:: Dat bien duong dan
set "VENV_PATH=F:\Real Project trust\.venv\Scripts\Activate.ps1"
set "WORKING_DIR=F:\Real Project trust\network_flow_collector_windows\web application"

:: Chay PowerShell voi quyen admin vao dung thu muc web application va chay python setup_and_run.py
powershell -Command "Start-Process powershell -ArgumentList '-NoExit', '-Command', '& ''%VENV_PATH%''; Set-Location ''%WORKING_DIR%''; python setup_and_run.py integrate --collector-path ''../network_flow_collector_windows/network_flow_collector_windows.py'' --server-url ''%SERVER_URL%''' -Verb RunAs"

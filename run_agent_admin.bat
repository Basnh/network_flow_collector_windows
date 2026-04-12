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

:: Dat bien duong dan dong (tu dong nhan dien o dia va thu muc)
set "CURRENT_DIR=%~dp0"
:: Xoa dau backslash o cuoi chuoi
set "CURRENT_DIR=%CURRENT_DIR:~0,-1%"

set "WORKING_DIR=%CURRENT_DIR%\web application"
set "COLLECTOR_PATH=%CURRENT_DIR%\network_flow_collector_windows.py"

:: Chay PowerShell voi quyen admin vao dung thu muc web application va chay python setup_and_run.py
powershell -Command "Start-Process powershell -ArgumentList '-NoExit', '-Command', 'Set-Location ''%WORKING_DIR%''; python setup_and_run.py integrate --collector-path ''%COLLECTOR_PATH%'' --server-url ''%SERVER_URL%''' -Verb RunAs"

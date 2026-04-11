@echo off
echo Dang yeu cau quyen Administrator de thu thap goi tin...

:: Dat bien duong dan
set "VENV_PATH=F:\Real Project trust\.venv\Scripts\Activate.ps1"
set "WORKING_DIR=F:\Real Project trust\network_flow_collector_windows"
set "APP_PATH=web application\setup_and_run.py"
set "COLLECTOR_PATH=network_flow_collector_windows.py"

:: Chay PowerShell voi quyen admin va xu ly nhay kep (cho phep co khoang trang)
powershell -Command "Start-Process powershell -ArgumentList '-NoExit', '-Command', '& ''%VENV_PATH%''; Set-Location ''%WORKING_DIR%''; python ''%APP_PATH%'' integrate --collector-path ''%COLLECTOR_PATH%''' -Verb RunAs"

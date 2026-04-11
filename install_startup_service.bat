@echo off
title Cai dat Network Flow Collector Service
echo Dang yeu cau quyen quan tri (Administrator) de cai dat...

:: Kiem tra quyen Admin
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :START_INSTALL
) else (
    echo Vui long chay file nay duoi quyen Administrator (Run as administrator)
    echo Cach lam: Click chuot phai vao file -^> Run as administrator.
    pause
    exit /b 1
)

:START_INSTALL
echo ----------------------------------------------------
echo DANG CAI DAT CHUONG TRINH THANH WINDOWS SERVICE...
echo ----------------------------------------------------

:: Lay duong dan tuyet doi cua thu muc hien tai
set "SCRIPT_DIR=%~dp0"
set "VBS_FILE=%SCRIPT_DIR%run_agent_hidden.vbs"

if not exist "%VBS_FILE%" (
    echo [LOI] Khong tim thay file: "%VBS_FILE%"
    pause
    exit /b 1
)

:: Tao Task ngam chay tren he thong
::  /ru SYSTEM: Chay duoi quyen cao nhat (he thong), bo qua man hinh UAC.
::  /rl HIGHEST: Dam bao NPcap co the hoat dong bat ky luc nao.
::  /sc ONSTART: Tu dong kich hoat khi Windows khoi dong len.
schtasks /create /f /tn "NetworkFlowCollectorAgent" /tr "wscript.exe \"%VBS_FILE%\"" /sc onstart /ru SYSTEM /rl HIGHEST

if %errorLevel% == 0 (
    echo.
    echo [THANH CONG] Da thiet lap chuong trinh chay cung Windows bang Task Scheduler.
    echo Tu bay gio, moi khi may Agent khoi dong, chuong trinh se tu hoat dong ngam.
    echo.
    set /p start_now="Ban co muon khoi dong service ngay bay gio khong? (Y/N): "
    if /i "%start_now%"=="Y" (
        schtasks /run /tn "NetworkFlowCollectorAgent"
        echo Da ra lenh bat dau thu thap.
    )
) else (
    echo.
    echo [THAT BAI] Qua trinh dang ky gap loi.
)

pause
exit /b 0
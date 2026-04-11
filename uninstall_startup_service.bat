@echo off
title Go bo Network Flow Collector Service
echo Dang yeu cau quyen quan tri (Administrator) de xoa bo...

:: Kiem tra quyen Admin
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :START_UNINSTALL
) else (
    echo Vui long chay file nay duoi quyen Administrator (Run as administrator)
    echo Cach lam: Click chuot phai vao file -^> Run as administrator.
    pause
    exit /b 1
)

:START_UNINSTALL
echo ----------------------------------------------------
echo GO BO SYSTEM SERVICE...
echo ----------------------------------------------------

:: Xoa Task khoi dong cung he thong
schtasks /delete /f /tn "NetworkFlowCollectorAgent" >nul 2>&1
if %errorLevel% == 0 (
    echo [THANH CONG] Da go bo chuong trinh khoi dong cung Windows.
    echo He thong Agent tren may nay se khong the tu mo len nua.

    set /p kill_now="Ban co muon dung chuong trinh dang chay hien tai khong? (Y/N): "
    if /i "%kill_now%"=="Y" (
        taskkill /f /im pythonw.exe >nul 2>&1
        echo Da cham dut cac tien trinh Python an (Luu y: viec nay the ngung toan bo cac ung dung Python chay ngam khac).
    )
) else (
    echo [THONG BAO] Khong the go bo. Co the chuong trinh chua tung duoc cai dat.
)

pause
exit /b 0
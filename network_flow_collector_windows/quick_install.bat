@echo off
echo === Quick Install Script for Network Flow Collector ===
echo.

echo Checking Python...
python --version
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found!
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo Installing required packages...
echo This may take a few minutes...
echo.

pip install --upgrade pip

echo Installing core packages...
pip install pandas==2.1.4
pip install numpy==1.24.3
pip install scapy==2.5.0
pip install matplotlib==3.7.2
pip install seaborn==0.13.2
pip install pywin32==306

echo.
echo Testing installation...
python -c "import pandas, numpy, scapy, matplotlib, seaborn; print('✓ All packages installed successfully')"

if %ERRORLEVEL% EQ 0 (
    echo.
    echo === Installation Complete! ===
    echo.
    echo You can now run:
    echo   python network_flow_collector_windows.py --list-interfaces
    echo.
) else (
    echo.
    echo === Installation Issues ===
    echo Some packages may not have installed correctly.
    echo Try running: pip install -r requirements.txt
    echo.
)

pause
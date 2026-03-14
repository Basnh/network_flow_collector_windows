@echo off
:: Run Security Agent Client as Administrator
:: Double-click this file to start the agent

setlocal

:: Change to the script directory
cd /d "%~dp0web application"

:: Check if we have a server argument
set SERVER_URL=http://localhost:5000
if not "%1"=="" set SERVER_URL=%1

echo.
echo  ======================================================
echo   Security Agent Client - Network Isolation Agent
echo  ======================================================
echo.
echo  Server: %SERVER_URL%
echo.
echo  NOTE: UAC prompt will appear - click YES to allow
echo        Administrator rights (required for network isolation)
echo.

:: Use PowerShell to start with elevation
powershell -Command "Start-Process python -ArgumentList 'security_agent_client.py --server %SERVER_URL%' -Verb RunAs -WorkingDirectory '%CD%'"

echo.
echo  Agent launched. Check the new window for status.
pause

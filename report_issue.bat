@echo off
setlocal enabledelayedexpansion

title LabWatch - Workstation Emergency Issue Reporting

echo ==============================================================================
echo  MEPCO SCHLENK ENGINEERING COLLEGE (AUTONOMOUS), SIVAKASI
echo  Department of Artificial Intelligence and Data Science (AIDS)
echo  Workstation Desk Issue Reporter (Zero-Phone Direct Desk Access)
echo ==============================================================================
echo.

:: 1. Auto-detect local workstation IP address
set "WORKSTATION_IP="
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    set "IP_CANDIDATE=%%a"
    set "IP_CANDIDATE=!IP_CANDIDATE: =!"
    if not "!IP_CANDIDATE!"=="" (
        set "WORKSTATION_IP=!IP_CANDIDATE!"
        goto :ip_found
    )
)

:ip_found
if "!WORKSTATION_IP!"=="" set "WORKSTATION_IP=127.0.0.1"

echo [+] Detected Workstation Network IP: !WORKSTATION_IP!
echo [*] Connecting to Department LabWatch Server...
echo [*] Launching Zero-Typing Issue Reporting Portal...
echo.

:: 2. Launch browser directly to /report
start "" "http://127.0.0.1:5000/report?client_ip=!WORKSTATION_IP!"

echo [OK] Portal opened in default web browser.
echo      Your workstation seat has been auto-detected.
echo.
timeout /t 3 >nul
exit /b 0

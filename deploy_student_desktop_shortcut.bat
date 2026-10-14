@echo off
setlocal enabledelayedexpansion

title LabWatch - Student Desktop Shortcut Deployer

echo ==============================================================================
echo  MEPCO SCHLENK ENGINEERING COLLEGE (AUTONOMOUS), SIVAKASI
echo  Department of Artificial Intelligence and Data Science (AIDS)
echo  LabWatch - Student Workstation Desktop Shortcut Deployer
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

:: 2. Set Server Address
set "SERVER_HOST=127.0.0.1"
if not "%~1"=="" set "SERVER_HOST=%~1"
echo [*] LabWatch Central Server Target: http://%SERVER_HOST%:5000

:: 3. Determine Desktop Path (Public Desktop for all students on this PC)
set "DESKTOP_DIR=%PUBLIC%\Desktop"
if not exist "%DESKTOP_DIR%" set "DESKTOP_DIR=%USERPROFILE%\Desktop"

set "SHORTCUT_PATH=%DESKTOP_DIR%\Report Lab PC Fault.url"

echo [*] Creating Desktop Shortcut at: "%SHORTCUT_PATH%"...

(
    echo [InternetShortcut]
    echo URL=http://%SERVER_HOST%:5000/report?client_ip=!WORKSTATION_IP!
    echo IconIndex=14
    echo IconFile=C:\Windows\System32\shell32.dll
    echo HotKey=0
) > "%SHORTCUT_PATH%"

if exist "%SHORTCUT_PATH%" (
    echo [+] SUCCESS: Desktop shortcut created successfully!
    echo     Location : "%SHORTCUT_PATH%"
    echo     Target   : http://%SERVER_HOST%:5000/report?client_ip=!WORKSTATION_IP!
    echo.
    echo [*] Students can now report any hardware or software fault directly from
    echo     the desktop without typing or mobile phones.
) else (
    echo [ERROR] Failed to write desktop shortcut. Please run as Administrator.
)

echo.
timeout /t 5 >nul
exit /b 0

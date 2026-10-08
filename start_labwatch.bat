@echo off
setlocal enabledelayedexpansion

title LabWatch - Mepco Schlenk Engineering College (AIDS Dept)

echo ==============================================================================
echo  MEPCO SCHLENK ENGINEERING COLLEGE (AUTONOMOUS), SIVAKASI
echo  Department of Artificial Intelligence and Data Science (AIDS)
echo  LabWatch - Laboratory PC Fault Reporting & Monitoring System
echo ==============================================================================
echo.

:: 1. Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 is not installed or not in system PATH!
    echo Please install Python 3.10+ from python.org or Microsoft Store.
    pause
    exit /b 1
)

:: 2. Ensure C binary is built
if not exist "bin\labpulse_monitor.exe" (
    echo [*] Compiled C network protocols binary not found.
    echo [*] Running automated build via build.bat...
    call build.bat
    if not exist "bin\labpulse_monitor.exe" (
        echo [!] Warning: Could not compile C daemon. Running in Python fallback mode.
    )
)

:: 3. Verify Database and Schema Migrations
echo [*] Verifying SQLite database and inventory schema...
python -c "import setup_db; conn = setup_db.get_db_connection(); setup_db.initialize_schema(conn); conn.close(); print('[+] Database verified successfully.')"

:: 4. Start Server and Launch Browser
echo.
echo [*] Starting LabWatch Institutional Server at http://127.0.0.1:5000...
echo [*] Press Ctrl+C in this console to stop the server.
echo.

start "" "http://127.0.0.1:5000"

python python_server.py 5000

pause

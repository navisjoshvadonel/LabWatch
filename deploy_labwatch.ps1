# ==============================================================================
# deploy_labwatch.ps1
# Mepco Schlenk Engineering College (Autonomous), Sivakasi
# Department of Artificial Intelligence and Data Science (AIDS)
# LabWatch -- Production Institutional Deployment Runner
# ==============================================================================

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host " MEPCO SCHLENK ENGINEERING COLLEGE (AUTONOMOUS), SIVAKASI" -ForegroundColor White
Write-Host " Department of Artificial Intelligence and Data Science (AIDS)" -ForegroundColor Cyan
Write-Host " LabWatch Institutional Deployment Suite" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "[ERROR] Python 3 was not found in PATH. Please install Python 3.10+."
    exit 1
}
Write-Host "[+] Python environment detected: $(python --version)" -ForegroundColor Green

# 2. Check C Binary
if (-not (Test-Path "bin\labpulse_monitor.exe")) {
    Write-Host "[*] C Network Daemon binary not found. Running build.bat..." -ForegroundColor Yellow
    cmd /c build.bat
} else {
    Write-Host "[+] C Network Daemon binary verified (bin\labpulse_monitor.exe)." -ForegroundColor Green
}

# 3. Database Integrity & Schema
Write-Host "[*] Checking SQLite Database and Schema Integrity..." -ForegroundColor Cyan
python -c "import setup_db; conn = setup_db.get_db_connection(); setup_db.initialize_schema(conn); c = conn.cursor(); c.execute('PRAGMA integrity_check'); res = c.fetchone()[0]; conn.close(); print('[+] Database Integrity: ' + str(res))"

# 4. Enumerate Active IPv4 Addresses
$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -ExpandProperty IPAddress
Write-Host "`n[*] Active Institutional LAN Access Points:" -ForegroundColor White
Write-Host "    - Localhost Portal     : http://127.0.0.1:5000" -ForegroundColor Gray
foreach ($ip in $ipAddresses) {
    Write-Host "    - Campus Network Access: http://${ip}:5000" -ForegroundColor Green
}
Write-Host "    - Student Report Form  : http://127.0.0.1:5000/report" -ForegroundColor Gray
Write-Host "    - IT Admin Triage Hub  : http://127.0.0.1:5000/admin" -ForegroundColor Gray
Write-Host "    - Digital Twin Floor   : http://127.0.0.1:5000/monitor" -ForegroundColor Gray
Write-Host "    - Deployment Status API: http://127.0.0.1:5000/api/deployment/status" -ForegroundColor Gray

Write-Host "`n[*] Opening default web browser..." -ForegroundColor Yellow
Start-Process "http://127.0.0.1:5000"

Write-Host "[*] Starting LabWatch Server on port 5000 (Press Ctrl+C to terminate)...`n" -ForegroundColor Cyan
python python_server.py 5000

@echo off
setlocal enabledelayedexpansion

echo ==============================================================================
echo  Building LabPulse Step 2: Core Network Protocols (C Implementation)
echo ==============================================================================

set MINGW_BIN=C:\Users\SNOW\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin
if exist "%MINGW_BIN%" set PATH=%MINGW_BIN%;%PATH%
if exist "C:\MinGW\bin" set PATH=C:\MinGW\bin;%PATH%
if exist "C:\msys64\ucrt64\bin" set PATH=C:\msys64\ucrt64\bin;%PATH%
if exist "C:\msys64\mingw64\bin" set PATH=C:\msys64\mingw64\bin;%PATH%

where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] GCC / Clang compiler not found in PATH!
    exit /b 1
)

if not exist bin mkdir bin

echo [*] Compiling C network protocols into standalone binary 'bin\labpulse_monitor.exe'...
gcc -O2 -Wall -Wextra -I./c_src ^
    c_src/main.c ^
    c_src/icmp.c ^
    c_src/udp.c ^
    c_src/tcp.c ^
    -lws2_32 -liphlpapi ^
    -o bin\labpulse_monitor.exe

if %errorlevel% equ 0 (
    echo [+] Compilation SUCCESSFUL!
    echo [+] Output binary created at: bin\labpulse_monitor.exe
    echo.
    echo [*] To run commands, use:
    echo     bin\labpulse_monitor.exe --help
    echo     bin\labpulse_monitor.exe --ping-pc PC-30
    echo     bin\labpulse_monitor.exe --restart PC-30
    echo     bin\labpulse_monitor.exe --sweep
) else (
    echo [ERROR] Compilation failed!
    exit /b %errorlevel%
)

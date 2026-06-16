@echo off
REM ============================================================
REM  UniFi AI Dashboard launcher
REM  Kills any running instance, then (re)launches the Flask app.
REM  app.py opens the browser itself via webbrowser.open().
REM ============================================================

cd /d "%~dp0"

echo Stopping any running instance...

REM 1) Kill whatever is listening on the Flask port (127.0.0.1:5000)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr "127.0.0.1:5000" ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)

REM 2) Kill any python running app.py (covers the debug reloader's child process)
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match 'app\.py' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

REM Give the OS a moment to release the socket
timeout /t 1 /nobreak >nul

echo Launching UniFi AI Dashboard...
start "UniFi AI Dashboard" python app.py

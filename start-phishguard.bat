@echo off
echo ==========================================
echo   🛡️  Starting PhishGuard
echo ==========================================
echo.
echo Flask CNN will be auto-started by Java.
echo Starting dashboard in browser...
timeout /t 5 /nobreak > nul
start http://localhost:8080
echo.
echo Now click RUN in IntelliJ to start Java.
pause

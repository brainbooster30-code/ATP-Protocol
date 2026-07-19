@echo off
REM ============================================================
REM  ATP SDK — Auto-install for TEACHER CLIENT (Windows)
REM  Nessuna configurazione di rete necessaria.
REM ============================================================
echo.
echo   🏠  ATP Teacher Client — Installazione Windows
echo   =============================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   ❌ Python non trovato. Installa Python 3.10+ da https://python.org
    pause
    exit /b 1
)
echo   ✅ Python trovato:
python --version

set ATP_DIR=%USERPROFILE%\atp-teacher-client
if not exist "%ATP_DIR%" mkdir "%ATP_DIR%"
cd /d "%ATP_DIR%"

echo.
echo   📦 Download ATP protocol...
if exist "ATP" (
    cd ATP && git pull 2>nul && cd ..
) else (
    git clone https://github.com/nousresearch/atp.git ATP 2>nul || (
        echo   📋 Copia i file ATP in %ATP_DIR%\ATP\
        mkdir ATP 2>nul
    )
)

echo.
echo   📦 Installazione dipendenze...
pip install aiohttp blake3 cbor2 cryptography pyngrok 2>&1 | findstr /V "already satisfied"

echo.
echo   ✅ Installazione completata!
echo.
echo   Per connetterti al server della scuola:
echo     cd %ATP_DIR%\ATP\sdk\examples
echo     python teacher_client.py atp_key_scuola_futura.card
echo.
echo   Il file .card te lo dà la scuola (USB, email, QR, WhatsApp).
echo   Nessuna configurazione di rete necessaria.
echo.
pause

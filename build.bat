@echo off
setlocal
chcp 65001 >nul
title Inkvizitor - EXE Builder (ShashevPro)
cd /d "%~dp0"

echo ============================================================
echo   INKVIZITOR - building Windows EXE
echo   ShashevPro - https://www.shashevpro.ru/
echo ============================================================
echo.

REM --- 1. Check Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH. Install Python 3.10+ and retry.
    pause
    exit /b 1
)

REM --- 2. Install dependencies and PyInstaller ---
echo [1/4] Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo.

REM --- 3. Clean previous build ---
echo [2/4] Cleaning previous build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist Inkvizitor.spec del /q Inkvizitor.spec
echo.

REM --- 4. Build single-file GUI EXE ---
echo [3/4] Building EXE with PyInstaller (this may take a minute)...
python -m PyInstaller --noconfirm --clean --onefile --windowed^
 --name Inkvizitor^
 --icon "assets\icon.ico"^
 --add-data "assets;assets"^
 --hidden-import colorama^
 --hidden-import charset_normalizer^
 main.py
if errorlevel 1 (
    echo [ERROR] Build failed. See messages above.
    pause
    exit /b 1
)
echo.

echo [4/4] Done.
echo ------------------------------------------------------------
echo   Result: dist\Inkvizitor.exe
echo ------------------------------------------------------------
echo.
echo Note: this builds the GUI app (no console window).
echo For console / CI use, run from source: python main.py ^<path^>
echo.
pause
endlocal

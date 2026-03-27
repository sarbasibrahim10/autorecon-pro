@echo off
title AutoRecon Pro - Setup
color 0B

echo.
echo  =========================================
echo   AutoRecon Pro - Setup Script
echo  =========================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Downloading Python 3.11...
    echo.
    :: Download Python installer
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe' -OutFile '%TEMP%\python_setup.exe' }"
    echo [*] Installing Python 3.11...
    %TEMP%\python_setup.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
    echo [*] Python installed. Please restart this script.
    pause
    exit /b 0
)

:: Show Python version
python --version
echo.

:: Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip -q

:: Install requirements
echo [*] Installing requirements...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Some packages failed. Trying one by one...
    python -m pip install httpx[http2] aiohttp aiofiles rich click aiosqlite
    python -m pip install dnspython pydantic beautifulsoup4 lxml jinja2
    python -m pip install python-whois tldextract yarl colorama anyio
)

echo.
echo  =========================================
echo   [OK] Setup complete!
echo  =========================================
echo.
echo  Usage:
echo    python main.py scan --target example.com
echo    python main.py scan --target example.com --no-nuclei
echo    python main.py scan --target example.com --resume
echo.
echo  Options:
echo    --target    Target domain (required)
echo    --output    Output directory (default: ./reports)
echo    --concurrency  Max concurrent requests (default: 50)
echo    --timeout   Request timeout seconds (default: 10)
echo    --resume    Resume previous scan
echo    --no-nuclei Skip Nuclei scanning
echo    --rps       Requests per second (default: 10)
echo.
pause

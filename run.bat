@echo off
:: AutoRecon Pro - Quick launcher
:: Usage: run.bat example.com [options]
if "%1"=="" (
    echo Usage: run.bat ^<target^> [--no-nuclei] [--resume] [--concurrency 50]
    echo.
    echo Examples:
    echo   run.bat example.com
    echo   run.bat hackerone.com --concurrency 30
    echo   run.bat bugcrowd.com --no-nuclei
    echo   run.bat testphp.vulnweb.com --resume
    pause
    exit /b 1
)
python main.py scan --target %*

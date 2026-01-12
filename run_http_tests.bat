@echo off
echo ========================================
echo HTTP Attack Testing for AttackReplay Pro
echo ========================================
echo.

echo Choose testing option:
echo 1. Simple HTTP Tester (Quick - 10 basic attacks)
echo 2. Comprehensive HTTP Tester (Full - All attack types)
echo 3. Exit
echo.

set /p choice="Enter your choice (1-3): "

if "%choice%"=="1" (
    echo.
    echo Running Simple HTTP Tester...
    echo.
    python simple_http_tester.py
    pause
) else if "%choice%"=="2" (
    echo.
    echo Running Comprehensive HTTP Tester...
    echo.
    python http_attack_tester.py
    pause
) else if "%choice%"=="3" (
    echo Exiting...
    exit /b 0
) else (
    echo Invalid choice. Please run the script again.
    pause
)
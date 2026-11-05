@echo off
rem WebTechSentry launcher for Windows - double-click this file.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 run.py %*
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        python run.py %*
    ) else (
        echo Python 3 is not installed. Get it from https://www.python.org/downloads/ and tick "Add Python to PATH".
    )
)
echo.
pause

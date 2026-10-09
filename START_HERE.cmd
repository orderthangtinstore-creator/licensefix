@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -File "%~dp0LicenseFix.ps1"
echo.
pause

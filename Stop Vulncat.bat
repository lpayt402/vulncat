@echo off
title Stop Vulncat
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -File "%~dp0scripts\Stop-Vulnerability-Workbench.ps1"
echo.
pause

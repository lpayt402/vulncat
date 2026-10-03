@echo off
title Vulncat Status
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -File "%~dp0scripts\Status-Vulnerability-Workbench.ps1"
echo.
pause

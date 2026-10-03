@echo off
title Vulncat
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -File "%~dp0scripts\Start-Vulnerability-Workbench.ps1"
if errorlevel 1 (
  echo.
  pause
)

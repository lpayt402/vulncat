@echo off
title Back Up Vulncat Database
cd /d "%~dp0"
echo This creates a Vulncat DATABASE backup.
echo.
echo A complete recovery set must also include the uploads and reports volumes.
echo See docs\backup-restore.md for the complete procedure.
echo.
powershell.exe -NoLogo -NoProfile -File "%~dp0scripts\backup-db.ps1"
echo.
pause

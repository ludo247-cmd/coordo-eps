@echo off
title Serveur Coordo-EPS
echo ============================================================
echo   Lancement du serveur local Coordo-EPS
echo ============================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0serveur-local.ps1" -Port 8080
pause

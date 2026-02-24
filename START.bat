@echo off
title WebSecurity SaaS Pro - Startup
color 0A

echo.
echo ======================================================
echo    WEBSECURITY SAAS PRO - v2.0
echo    Plateforme de Cybersecurite Avancee
echo ======================================================
echo.

cd /d "%~dp0"

echo [1/4] Verification de Node.js...
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Node.js n'est pas installe !
    echo Telechargez Node.js depuis https://nodejs.org/
    pause
    exit /b 1
)

node --version
echo [OK] Node.js detecte
echo.

echo [2/4] Installation des dependances backend...
cd backend
if not exist node_modules (
    echo Installation en cours...
    call npm install
    if %ERRORLEVEL% NEQ 0 (
        echo [ERREUR] Echec de l'installation des dependances
        pause
        exit /b 1
    )
) else (
    echo Dependencies deja installees
)
echo [OK] Dependencies backend ready
echo.

echo [3/4] Initialisation de la base de donnees...
node init-db.js
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Echec de l'initialisation de la base
    pause
    exit /b 1
)
echo [OK] Base de donnees initialisee
echo.

echo [4/4] Demarrage du serveur...
echo.
echo ======================================================
echo   Serveur demarre avec succes !
echo ======================================================
echo.
echo   Frontend:  http://localhost:3000/
echo   Login:     http://localhost:3000/login.html
echo   Dashboard: http://localhost:3000/dashboard.html
echo.
echo   Compte demo:
echo   Email:     demo@websecurity.com
echo   Password:  demo123
echo.
echo ======================================================
echo   Appuyez sur Ctrl+C pour arreter le serveur
echo ======================================================
echo.

node server.js

pause

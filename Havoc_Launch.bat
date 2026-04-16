@echo off
title Havoc Security Platform Launcher
color 0c

echo ===================================================
echo     HAVOC SECURITY PLATFORM - 1-CLICK LAUNCHER
echo ===================================================
echo.
echo Please wait while the platform initializes...
echo.

echo [1/2] Starting Python Backend API (api_server.py)...
start "Havoc Backend API" cmd /k "python api_server.py"

echo [2/2] Starting React Frontend Dashboard...
start "Havoc Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ===================================================
echo Both services have been launched in separate windows!
echo Your browser should automatically open the dashboard.
echo If not, navigate to http://localhost:5173
echo ===================================================
echo.
pause

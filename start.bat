@echo off
REM ──────────────────────────────────────────────────────────────
REM  Havoc Security – AutoVAPT-AI Start Script
REM  Starts both Flask API (port 5000) and React dev server (port 5173)
REM ──────────────────────────────────────────────────────────────

echo Starting Flask API server on http://localhost:5000 ...
start "Flask API" cmd /c "cd %~dp0 && pip install flask-cors -q && python api_server.py"

echo Waiting for Flask to start...
timeout /t 3 /nobreak > nul

echo Starting React dev server on http://localhost:5173 ...
start "React Frontend" cmd /c "cd %~dp0frontend && npm run dev"

echo.
echo ============================================
echo  Havoc Security Dashboard is starting up!
echo  Open your browser at: http://localhost:5173
echo ============================================
timeout /t 3 /nobreak > nul
start http://localhost:5173

@echo off
setlocal
cd /d "%~dp0"
set KAZEVAULT_MODE=remote
set KAZEVAULT_HTTPS=1
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8765

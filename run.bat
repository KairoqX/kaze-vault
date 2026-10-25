@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (echo Run: py -m venv .venv ^& .venv\Scripts\pip install -r requirements.txt & exit /b 1)
set KAZEVAULT_HTTPS=0
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8765


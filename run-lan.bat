@echo off
setlocal
cd /d "%~dp0"
set KAZEVAULT_MODE=lan
.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8765


@echo off
setlocal
cd /d "%~dp0"
set KAZEVAULT_MODE=remote
set KAZEVAULT_HTTPS=1
set KAZEVAULT_LLAMA_SERVER=F:\llama\llama-server.exe
set KAZEVAULT_LLAMA_ENDPOINT=http://127.0.0.1:8081
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8765

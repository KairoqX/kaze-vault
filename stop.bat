@echo off
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8765"') do taskkill /PID %%a /T /F


@echo off
cd /d "%~dp0"
start "Host Bridge" cmd /k call "%cd%\scripts\run_host_bridge.bat"
docker compose up --build
pause
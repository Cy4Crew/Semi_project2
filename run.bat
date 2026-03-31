@echo off
chcp 65001 > nul

echo [*] Stopping existing containers and volumes...
docker compose down -v
if errorlevel 1 goto :fail

echo [*] Rebuilding images without cache...
docker compose build --no-cache
if errorlevel 1 goto :fail

echo [*] Starting fresh containers...
docker compose up -d
if errorlevel 1 goto :fail

echo [*] Done. Opening app logs...
docker compose logs -f app
exit /b 0

:fail
echo [!] Docker command failed.
exit /b 1

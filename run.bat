@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "HOST_BRIDGE_ENV=scripts\host_bridge.env"
set "PROJECT_ENV=.env"
set "PROJECT_ENV_FALLBACK=.env.example"

if exist "%HOST_BRIDGE_ENV%" (
    echo [INFO] Loading %HOST_BRIDGE_ENV%
    call :load_env_file "%HOST_BRIDGE_ENV%"
) else (
    echo [WARN] %HOST_BRIDGE_ENV% not found. Using built-in defaults and .env values.
)

if exist "%PROJECT_ENV%" (
    echo [INFO] Loading %PROJECT_ENV%
    call :load_env_file "%PROJECT_ENV%"
) else if exist "%PROJECT_ENV_FALLBACK%" (
    echo [WARN] %PROJECT_ENV% not found. Using defaults from %PROJECT_ENV_FALLBACK% where possible.
    call :load_env_file "%PROJECT_ENV_FALLBACK%"
) else (
    echo [WARN] No %PROJECT_ENV% or %PROJECT_ENV_FALLBACK% found. Using hard-coded defaults.
)

if not defined BRIDGE_PORT set "BRIDGE_PORT=9080"
if not defined API_HOST set "API_HOST=0.0.0.0"
if not defined API_PORT set "API_PORT=8000"
if not defined SAMPLE_TIMEOUT_SECONDS set "SAMPLE_TIMEOUT_SECONDS=5"
if not defined SANDBOX_BACKEND set "SANDBOX_BACKEND=auto"
if not defined SANDBOX_VM_NAME set "SANDBOX_VM_NAME=win10x64"
if not defined SANDBOX_VM_SNAPSHOT set "SANDBOX_VM_SNAPSHOT=clean"
if not defined SANDBOX_JOB_TIMEOUT_SECONDS set "SANDBOX_JOB_TIMEOUT_SECONDS=180"
if not defined SANDBOX_DISABLE_NETWORK set "SANDBOX_DISABLE_NETWORK=true"
if not defined SANDBOX_REQUIRE_DYNAMIC_SUCCESS set "SANDBOX_REQUIRE_DYNAMIC_SUCCESS=false"
if not defined ENABLE_PCAP set "ENABLE_PCAP=false"
if not defined SURICATA_BINARY set "SURICATA_BINARY="
if not defined SURICATA_RULES_PATH set "SURICATA_RULES_PATH=./rules/suricata.rules"
if not defined VOLATILITY3_BINARY set "VOLATILITY3_BINARY="
if not defined MONITOR_LOGS_DIR set "MONITOR_LOGS_DIR=C:\analysis\monitor"
if not defined REPORT_DB_PATH set "REPORT_DB_PATH=./artifacts/reports.db"
if not defined HOST_BRIDGE_START_TIMEOUT_SECONDS set "HOST_BRIDGE_START_TIMEOUT_SECONDS=45"

if not defined DOCKER_API_PORT set "DOCKER_API_PORT=%API_PORT%"
if not defined DOCKER_CONTAINER_API_PORT set "DOCKER_CONTAINER_API_PORT=8000"
if not defined DOCKER_API_HOST set "DOCKER_API_HOST=%API_HOST%"
if not defined DOCKER_SAMPLE_TIMEOUT_SECONDS set "DOCKER_SAMPLE_TIMEOUT_SECONDS=%SAMPLE_TIMEOUT_SECONDS%"
if not defined DOCKER_SANDBOX_BACKEND set "DOCKER_SANDBOX_BACKEND=%SANDBOX_BACKEND%"
if not defined DOCKER_SANDBOX_VM_NAME set "DOCKER_SANDBOX_VM_NAME=%SANDBOX_VM_NAME%"
if not defined DOCKER_SANDBOX_VM_SNAPSHOT set "DOCKER_SANDBOX_VM_SNAPSHOT=%SANDBOX_VM_SNAPSHOT%"
if not defined DOCKER_SANDBOX_JOB_TIMEOUT_SECONDS set "DOCKER_SANDBOX_JOB_TIMEOUT_SECONDS=%SANDBOX_JOB_TIMEOUT_SECONDS%"
if not defined DOCKER_SANDBOX_DISABLE_NETWORK set "DOCKER_SANDBOX_DISABLE_NETWORK=%SANDBOX_DISABLE_NETWORK%"
if not defined DOCKER_SANDBOX_REQUIRE_DYNAMIC_SUCCESS set "DOCKER_SANDBOX_REQUIRE_DYNAMIC_SUCCESS=%SANDBOX_REQUIRE_DYNAMIC_SUCCESS%"
if not defined DOCKER_ENABLE_PCAP set "DOCKER_ENABLE_PCAP=%ENABLE_PCAP%"
if not defined DOCKER_SURICATA_BINARY set "DOCKER_SURICATA_BINARY=%SURICATA_BINARY%"
if not defined DOCKER_SURICATA_RULES_PATH set "DOCKER_SURICATA_RULES_PATH=%SURICATA_RULES_PATH%"
if not defined DOCKER_VOLATILITY3_BINARY set "DOCKER_VOLATILITY3_BINARY=%VOLATILITY3_BINARY%"
if not defined DOCKER_MONITOR_LOGS_DIR set "DOCKER_MONITOR_LOGS_DIR=%MONITOR_LOGS_DIR%"
if not defined DOCKER_REPORT_DB_PATH set "DOCKER_REPORT_DB_PATH=%REPORT_DB_PATH%"
if not defined DOCKER_SANDBOX_BRIDGE_URL set "DOCKER_SANDBOX_BRIDGE_URL=http://host.docker.internal:%BRIDGE_PORT%"

if defined COMPOSE_PROJECT_NAME set "COMPOSE_PROJECT_NAME=%COMPOSE_PROJECT_NAME%"

echo [STEP 1] Effective Docker/runtime configuration
for %%V in (
    BRIDGE_PORT
    API_PORT
    SANDBOX_BACKEND
    SANDBOX_VM_NAME
    SANDBOX_VM_SNAPSHOT
    SANDBOX_JOB_TIMEOUT_SECONDS
    SANDBOX_DISABLE_NETWORK
    SANDBOX_REQUIRE_DYNAMIC_SUCCESS
    ENABLE_PCAP
    DOCKER_API_PORT
    DOCKER_SANDBOX_BRIDGE_URL
    HOST_BRIDGE_START_TIMEOUT_SECONDS
) do (
    if defined %%V echo [INFO] %%V=!%%V!
)

echo [STEP 2] Starting Host Bridge in a new console window...
start "Host Bridge" cmd /k call "%cd%\scripts\run_host_bridge.bat"

echo [STEP 3] Waiting for Host Bridge HTTP listener...
call :wait_for_bridge_http
if errorlevel 1 (
    echo [ERROR] Host Bridge did not become reachable on http://localhost:%BRIDGE_PORT%/health
    pause
    exit /b 1
)

echo [STEP 4] Starting Docker application stack in this console...
docker compose up --build
pause
exit /b %errorlevel%

:wait_for_bridge_http
set /a _WAIT_REMAINING=%HOST_BRIDGE_START_TIMEOUT_SECONDS%
:wait_bridge_loop
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ProgressPreference='SilentlyContinue'; try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri 'http://localhost:%BRIDGE_PORT%/health?snapshot_name=%SANDBOX_VM_SNAPSHOT%26vm_name=%SANDBOX_VM_NAME%'; if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>nul
if not errorlevel 1 (
    echo [INFO] Host Bridge is reachable.
    exit /b 0
)
if %_WAIT_REMAINING% LEQ 0 exit /b 1
set /a _WAIT_REMAINING-=1
timeout /t 1 /nobreak >nul
goto wait_bridge_loop

:load_env_file
set "_ENV_PATH=%~1"
if not exist "%_ENV_PATH%" goto :eof
for /f "usebackq tokens=* delims=" %%L in ("%_ENV_PATH%") do (
    set "LINE=%%L"
    if defined LINE (
        if not "!LINE:~0,1!"=="#" (
            for /f "tokens=1* delims==" %%A in ("!LINE!") do (
                if not "%%~A"=="" set "%%~A=%%~B"
            )
        )
    )
)
goto :eof

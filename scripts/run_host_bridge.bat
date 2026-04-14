@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0\.."

set "ENV_FILE=scripts\host_bridge.env"

echo [STEP 1] Loading Host Bridge configuration...
if exist "%ENV_FILE%" (
    echo [INFO] Loading %ENV_FILE%
    for /f "usebackq tokens=* delims=" %%L in ("%ENV_FILE%") do (
        set "LINE=%%L"
        if defined LINE (
            if not "!LINE:~0,1!"=="#" (
                for /f "tokens=1* delims==" %%A in ("!LINE!") do (
                    if not "%%~A"=="" (
                        set "KEY=%%~A"
                        set "VAL=%%~B"
                        if defined KEY set "!KEY!=!VAL!"
                    )
                )
            )
        )
    )
) else (
    echo [WARN] No %ENV_FILE% found. Using auto-detection where possible.
)

if not defined VMRUN_PATH (
    if exist "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" set "VMRUN_PATH=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
)
if not defined VMRUN_PATH (
    if exist "C:\Program Files\VMware\VMware Workstation\vmrun.exe" set "VMRUN_PATH=C:\Program Files\VMware\VMware Workstation\vmrun.exe"
)

if not defined PYTHON_BIN (
    where py >nul 2>nul && set "PYTHON_BIN=py"
)
if not defined PYTHON_BIN (
    where python >nul 2>nul && set "PYTHON_BIN=python"
)
if not defined PYTHON_BIN (
    for %%P in ("%LocalAppData%\Programs\Python\Python313\python.exe" "%LocalAppData%\Programs\Python\Python312\python.exe" "%LocalAppData%\Programs\Python\Python311\python.exe" "%LocalAppData%\Programs\Python\Python310\python.exe") do (
        if not defined PYTHON_BIN if exist %%~P set "PYTHON_BIN=%%~P"
    )
)

if not defined BRIDGE_PORT set "BRIDGE_PORT=9080"
if not defined DEFAULT_VM_NAME set "DEFAULT_VM_NAME=win10x64"
if not defined DEFAULT_SNAPSHOT set "DEFAULT_SNAPSHOT=clean"
if not defined BRIDGE_WORK_DIR set "BRIDGE_WORK_DIR=%cd%\host_bridge\workspace"
if not defined BRIDGE_SHARED_DIR set "BRIDGE_SHARED_DIR=%BRIDGE_WORK_DIR%\shared"
if not defined HOST_BRIDGE_HOST set "HOST_BRIDGE_HOST=0.0.0.0"

echo [STEP 2] Effective Host Bridge configuration
if defined VMX_PATH echo [INFO] VMX_PATH=%VMX_PATH%
if defined VMRUN_PATH echo [INFO] VMRUN_PATH=%VMRUN_PATH%
if defined PYTHON_BIN echo [INFO] PYTHON_BIN=%PYTHON_BIN%
if defined BRIDGE_WORK_DIR echo [INFO] BRIDGE_WORK_DIR=%BRIDGE_WORK_DIR%
if defined BRIDGE_SHARED_DIR echo [INFO] BRIDGE_SHARED_DIR=%BRIDGE_SHARED_DIR%
if defined DEFAULT_VM_NAME echo [INFO] DEFAULT_VM_NAME=%DEFAULT_VM_NAME%
if defined DEFAULT_SNAPSHOT echo [INFO] DEFAULT_SNAPSHOT=%DEFAULT_SNAPSHOT%
if defined DEFAULT_TIMEOUT echo [INFO] DEFAULT_TIMEOUT=%DEFAULT_TIMEOUT%
if defined SOFT_STOP_WAIT_SECONDS echo [INFO] SOFT_STOP_WAIT_SECONDS=%SOFT_STOP_WAIT_SECONDS%
if defined BRIDGE_PORT echo [INFO] BRIDGE_PORT=%BRIDGE_PORT%

if not defined PYTHON_BIN (
    echo [ERROR] PYTHON_BIN is not set and Python auto-detection failed.
    pause
    exit /b 1
)
if defined VMX_PATH if not exist "%VMX_PATH%" (
    echo [ERROR] VMX_PATH does not exist: %VMX_PATH%
    pause
    exit /b 1
)
if defined VMRUN_PATH if not exist "%VMRUN_PATH%" (
    echo [ERROR] VMRUN_PATH does not exist: %VMRUN_PATH%
    pause
    exit /b 1
)
if defined VMRUN_PATH (
    "%VMRUN_PATH%" list >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] vmrun execute failed: %VMRUN_PATH%
        pause
        exit /b 1
    )
    echo [STEP 3] VMware vmrun check passed
) else (
    echo [WARN] VMRUN_PATH not set. Host Bridge will try its own auto-detection.
)

"%PYTHON_BIN%" -m pip install -r "host_bridge\requirements.txt"
if errorlevel 1 (
    echo [ERROR] pip install failed
    pause
    exit /b 1
)

echo [STEP 4] Starting Host Bridge on port %BRIDGE_PORT%
"%PYTHON_BIN%" -m uvicorn host_bridge.host_bridge:APP --host %HOST_BRIDGE_HOST% --port %BRIDGE_PORT%

pause

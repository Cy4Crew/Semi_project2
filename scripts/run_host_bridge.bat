@echo off
cd /d "%~dp0\.."
call scripts\host_bridge.local.bat

echo [INFO] VMX_PATH=%VMX_PATH%
echo [INFO] VMRUN_PATH=%VMRUN_PATH%

"%VMRUN_PATH%" list >nul 2>nul
if errorlevel 1 (
    echo [ERROR] vmrun execute failed: %VMRUN_PATH%
    pause
    exit /b 1
)

%PYTHON_BIN% -m pip install -r host_bridge\requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed
    pause
    exit /b 1
)

%PYTHON_BIN% -m uvicorn host_bridge.host_bridge:APP --host 0.0.0.0 --port 9080
pause
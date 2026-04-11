@echo off
if "%VMRUN_PATH%"=="" set VMRUN_PATH=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
if not exist "%VMRUN_PATH%" (
  echo vmrun.exe not found: %VMRUN_PATH%
  exit /b 1
)
"%VMRUN_PATH%" list

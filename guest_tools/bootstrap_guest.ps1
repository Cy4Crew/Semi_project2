param(
  [string]$SharedDir = "",
  [string]$WorkDir = "C:\sandbox_work",
  [string]$InstallDir = "C:\sandbox_agent"
)

if ($SharedDir -and -not (Test-Path $SharedDir)) { New-Item -ItemType Directory -Force -Path $SharedDir | Out-Null }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path ".\guest_agent.py" -Destination "$InstallDir\guest_agent.py" -Force
py -m pip install --upgrade pip
py -m pip install psutil
[Environment]::SetEnvironmentVariable("VM_WORK_DIR", $WorkDir, "Machine")
if ($SharedDir) {
  [Environment]::SetEnvironmentVariable("VM_SHARED_DIR", $SharedDir, "Machine")
} else {
  [Environment]::SetEnvironmentVariable("VM_SHARED_DIR", $null, "Machine")
}
$action = New-ScheduledTaskAction -Execute "py.exe" -Argument "`"$InstallDir\guest_agent.py`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
Register-ScheduledTask -TaskName "SandboxGuestAgent" -Action $action -Trigger $trigger -Principal $principal -Force
Start-ScheduledTask -TaskName "SandboxGuestAgent"
Write-Host "Guest agent installed. SharedDir=$SharedDir WorkDir=$WorkDir"

param(
  [string]$SharedDir = "",
  [string]$WorkDir = "C:\sandbox_work",
  [string]$InstallDir = "C:\sandbox_agent",
  [string]$ProcdumpPath = "",
  [string]$MonitorLogsDir = "",
  [switch]$StartNow
)

$ErrorActionPreference = "Stop"

function Resolve-PreferredPython {
  $candidates = @(
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python313\python.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312\python.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311\python.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python310\python.exe",
    "C:\Program Files\Python313\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python310\python.exe"
  )

  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) {
      return $candidate
    }
  }

  if (Get-Command py.exe -ErrorAction SilentlyContinue) {
    return (Get-Command py.exe).Source
  }
  if (Get-Command python.exe -ErrorAction SilentlyContinue) {
    return (Get-Command python.exe).Source
  }

  throw "64-bit Python was not found. Install 64-bit Python in the guest first."
}


function Set-EnvWithFallback {
  param(
    [string]$Name,
    [AllowNull()][string]$Value
  )

  try {
    [Environment]::SetEnvironmentVariable($Name, $Value, "Machine")
    return "Machine"
  } catch {
    try {
      [Environment]::SetEnvironmentVariable($Name, $Value, "User")
      return "User"
    } catch {
      [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
      return "Process"
    }
  }
}

$PythonExe = Resolve-PreferredPython
$PythonArch = & $PythonExe -c "import platform; print(platform.architecture()[0])"
if ($PythonArch -notmatch "64bit") {
  throw "Resolved Python is not 64-bit: $PythonExe ($PythonArch)"
}

if ($SharedDir -and -not (Test-Path $SharedDir)) {
  New-Item -ItemType Directory -Force -Path $SharedDir | Out-Null
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if (-not (Test-Path ".\guest_agent.py")) {
  throw "guest_agent.py was not found in the current directory. Run this script from the guest_tools folder."
}
$sourceAgent = (Resolve-Path ".\guest_agent.py").Path
$destAgent = [System.IO.Path]::GetFullPath((Join-Path $InstallDir "guest_agent.py"))
if ($sourceAgent -ne $destAgent) {
  Copy-Item -Path $sourceAgent -Destination $destAgent -Force
}

& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install psutil

$VMWorkDirScope = Set-EnvWithFallback -Name "VM_WORK_DIR" -Value $WorkDir
$VMPythonScope = Set-EnvWithFallback -Name "VM_PYTHON64" -Value $PythonExe

$ProcdumpScope = $null
if ($ProcdumpPath) {
  $ProcdumpScope = Set-EnvWithFallback -Name "PROCDUMP_PATH" -Value $ProcdumpPath
}
$MonitorLogsScope = $null
if ($MonitorLogsDir) {
  New-Item -ItemType Directory -Force -Path $MonitorLogsDir | Out-Null
  $MonitorLogsScope = Set-EnvWithFallback -Name "MONITOR_LOGS_DIR" -Value $MonitorLogsDir
}

function Resolve-GuestSharedDirCandidates {
  param(
    [AllowNull()][string]$Value
  )

  $candidates = New-Object System.Collections.Generic.List[string]
  if ($Value) {
    $trimmed = $Value.Trim()
    if ($trimmed) {
      $candidates.Add($trimmed)
      try {
        $leaf = Split-Path -Path $trimmed -Leaf
        if ($leaf) {
          $candidates.Add((Join-Path "\\vmware-host\Shared Folders" $leaf))
          $candidates.Add((Join-Path "Z:\" $leaf))
        }
      } catch {}
    }
  }
  $candidates.Add("\\vmware-host\Shared Folders\shared")
  $candidates.Add("\\vmware-host\Shared Folders\sandbox_shared")
  $candidates.Add("Z:\shared")
  $candidates.Add("Z:\sandbox_shared")
  $candidates.Add("C:\sandbox_shared")

  $seen = @{}
  $ordered = New-Object System.Collections.Generic.List[string]
  foreach ($candidate in $candidates) {
    if (-not $candidate) { continue }
    $key = $candidate.ToLowerInvariant()
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $ordered.Add($candidate)
  }
  return $ordered
}

$sharedCandidates = Resolve-GuestSharedDirCandidates -Value $SharedDir
$resolvedSharedDir = $null
foreach ($candidate in $sharedCandidates) {
  try {
    if (Test-Path $candidate) {
      $resolvedSharedDir = $candidate
      break
    }
  } catch {}
}
if (-not $resolvedSharedDir -and $sharedCandidates.Count -gt 0) {
  $resolvedSharedDir = $sharedCandidates[0]
}

$resolvedSharedDirName = $null
if ($resolvedSharedDir) {
  try {
    $resolvedSharedDirName = Split-Path -Path $resolvedSharedDir -Leaf
  } catch {
    $resolvedSharedDirName = $null
  }
}

$taskName = "SandboxGuestAgent"
$taskArgs = "`"$InstallDir\guest_agent.py`""
$action = New-ScheduledTaskAction -Execute $PythonExe -Argument $taskArgs
$triggers = @(
  (New-ScheduledTaskTrigger -AtStartup),
  (New-ScheduledTaskTrigger -AtLogOn)
)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Force | Out-Null

$VMSharedDirScope = Set-EnvWithFallback -Name "VM_SHARED_DIR" -Value $(if ($resolvedSharedDir) { $resolvedSharedDir } else { $null })
$VMSharedDirNameScope = Set-EnvWithFallback -Name "VM_SHARED_DIR_NAME" -Value $(if ($resolvedSharedDirName) { $resolvedSharedDirName } else { $null })

if ($StartNow) {
  Start-ScheduledTask -TaskName $taskName
} else {
  Start-ScheduledTask -TaskName $taskName
}

Write-Host "Guest agent installed successfully."
Write-Host "PythonExe=$PythonExe"
Write-Host "SharedDir=$SharedDir"
if ($resolvedSharedDir) { Write-Host "ResolvedSharedDir=$resolvedSharedDir" }
if ($resolvedSharedDirName) { Write-Host "ResolvedSharedDirName=$resolvedSharedDirName" }
Write-Host "WorkDir=$WorkDir"
Write-Host "InstallDir=$InstallDir"
if ($ProcdumpPath) { Write-Host "ProcdumpPath=$ProcdumpPath" }
if ($MonitorLogsDir) { Write-Host "MonitorLogsDir=$MonitorLogsDir" }
Write-Host "ScheduledTask=$taskName"
Write-Host "VM_WORK_DIR scope=$VMWorkDirScope"
Write-Host "VM_SHARED_DIR scope=$VMSharedDirScope"
if ($VMSharedDirNameScope) { Write-Host "VM_SHARED_DIR_NAME scope=$VMSharedDirNameScope" }
Write-Host "VM_PYTHON64 scope=$VMPythonScope"
if ($ProcdumpScope) { Write-Host "PROCDUMP_PATH scope=$ProcdumpScope" }
if ($MonitorLogsScope) { Write-Host "MONITOR_LOGS_DIR scope=$MonitorLogsScope" }
Write-Host ""
Write-Host "Recommended checks:"
Write-Host "  1. where python"
Write-Host '  2. & $PythonExe -c "import platform; print(platform.architecture())"'
Write-Host "  3. Verify VMware Shared Folders are visible inside the guest."
Write-Host ""
Write-Host "Examples:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\bootstrap_guest.ps1 -SharedDir '\\vmware-host\Shared Folders\shared' -StartNow"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\bootstrap_guest.ps1 -SharedDir '\\vmware-host\Shared Folders\sandbox_shared' -ProcdumpPath 'C:\Tools\Sysinternals\procdump64.exe' -MonitorLogsDir 'C:\analysis\monitor' -StartNow"

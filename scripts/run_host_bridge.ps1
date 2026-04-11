$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Load-EnvFile([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    Get-Content -Path $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), 'Process')
        }
    }
}

function First-ExistingPath([string[]]$Candidates) {
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    return $null
}

Load-EnvFile (Join-Path (Get-Location) 'scripts\host_bridge.env')

if (-not $env:VMRUN_PATH) {
    $env:VMRUN_PATH = First-ExistingPath @(
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
    )
}

if (-not $env:VMX_PATH) {
    $roots = @(
        'C:\VMs',
        [Environment]::GetFolderPath('MyDocuments'),
        $env:OneDrive,
        (Join-Path $env:USERPROFILE 'OneDrive\문서'),
        (Join-Path $env:USERPROFILE 'OneDrive\Documents')
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $vmx = foreach ($root in $roots) {
        Get-ChildItem -Path $root -Filter *.vmx -Recurse -ErrorAction SilentlyContinue |
            Sort-Object @{Expression = { if ($_.FullName -match 'win10x64|analysis|sandbox|malware') { 0 } else { 1 } }}, FullName |
            Select-Object -ExpandProperty FullName
    } | Select-Object -First 1

    if ($vmx) { $env:VMX_PATH = $vmx }
}

if (-not $env:PYTHON_BIN) {
    if (Get-Command py -ErrorAction SilentlyContinue) { $env:PYTHON_BIN = 'py' }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $env:PYTHON_BIN = 'python' }
}

if (-not $env:VMX_PATH) { throw 'VMX_PATH not found. Create scripts\host_bridge.env if auto-detect fails.' }
if (-not $env:VMRUN_PATH) { throw 'VMRUN_PATH not found. Create scripts\host_bridge.env if auto-detect fails.' }
if (-not $env:PYTHON_BIN) { throw 'Python not found on host.' }
if (-not (Test-Path $env:VMX_PATH)) { throw "VMX_PATH does not exist: $env:VMX_PATH" }
if (-not (Test-Path $env:VMRUN_PATH)) { throw "VMRUN_PATH does not exist: $env:VMRUN_PATH" }

Write-Host "[INFO] VMX_PATH=$env:VMX_PATH"
Write-Host "[INFO] VMRUN_PATH=$env:VMRUN_PATH"
Write-Host "[INFO] PYTHON_BIN=$env:PYTHON_BIN"

& $env:PYTHON_BIN -m pip install -r (Join-Path (Get-Location) 'host_bridge\requirements.txt')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $env:PYTHON_BIN -m uvicorn host_bridge.host_bridge:APP --app-dir (Get-Location).Path --host 0.0.0.0 --port 9080
exit $LASTEXITCODE

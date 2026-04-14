# README_VM

## Windows VM Setup Guide for Malware Sandbox

## 1. Required VM Storage Path (Critical)

Do NOT use VMware default storage path such as:

```text
C:\Users\<user>\Documents\Virtual Machines\Win10x64
```

Use this exact location instead:

```text
C:\Win10x64
```

The VMX file must exist here:

```text
C:\Win10x64\Win10x64.vmx
```

VMware project settings and host bridge configs expect this path.

## 2. Required VM Name

VM display name must be:

```text
Win10x64
```

## 3. Required OS Edition

Install:

```text
Windows 10 Pro x64
```

## 4. Recommended VM Specs

- CPU: 2-4 cores
- RAM: 4 GB minimum, 8 GB recommended
- Disk: 60 GB minimum
- Network: NAT

## 5. Install Order

1. Create VM using storage path `C:\Win10x64`
2. Install Windows 10 Pro
3. Disable Windows security features
4. Install VMware Tools
5. Install Microsoft Visual C++ Redistributables
6. Install Python 3.10 x64
7. Configure Shared Folder
8. Install Guest Agent
9. Create clean snapshot

## 6. Disable Security Features (Important)

Inside VM disable:

- Windows Defender Real-time Protection
- Tamper Protection
- SmartScreen
- Firewall (recommended in isolated lab only)
- User Account Control (UAC)
- Automatic Updates
- Sleep / Hibernate
- Controlled Folder Access

Reason:
Samples may be blocked, quarantined, or prevented from launching.

## 7. Required Packages

### VMware Tools

VMware menu:

```text
VM > Install VMware Tools
```

Reboot after installation.

### Microsoft Visual C++ Redistributable

Install both:

- vc_redist.x64.exe
- vc_redist.x86.exe

### Python

Recommended:

```text
Python 3.10 x64
```

Enable during install:

```text
Add Python to PATH
```

Verify:

```cmd
python --version
```

## 8. Shared Folder

Host path:

```text
host_bridge\workspace\shared
```

Guest shared folder name must be:

```text
shared
```

Verify inside VM:

```cmd
dir "\\vmware-host\Shared Folders\shared"
```

## 9. Guest Agent

Create:

```text
C:\sandbox_agent
```

Copy:

- guest_agent.py
- bootstrap_guest.ps1

Run in Administrator PowerShell:

```powershell
cd C:\sandbox_agent
Set-ExecutionPolicy Bypass -Scope Process -Force
.\bootstrap_guest.ps1
```

## 10. Validation

```powershell
Get-ScheduledTask -TaskName SandboxGuestAgent
```

```cmd
dir C:\sandbox_work
```

Heartbeat files should exist.

## 11. Snapshot

After everything works:

```text
VMware > Snapshot > Take Snapshot
```

Snapshot name:

```text
clean
```

## 12. Common Mistakes

- VM stored in Documents\Virtual Machines
- Wrong VM name
- Windows Home edition used
- Snapshot created before Guest Agent install
- Shared folder name mismatch
- VMware Tools missing
- Python PATH missing
- Defender still enabled
- Only x64 VC++ installed

## 13. Final Checklist

- VM folder = `C:\Win10x64`
- VMX path = `C:\Win10x64\Win10x64.vmx`
- VM name = `Win10x64`
- OS = Windows 10 Pro x64
- VMware Tools installed
- VC++ x64/x86 installed
- Python installed
- Security protections disabled
- Shared folder works
- Guest Agent running
- Snapshot `clean` created

# README_OPERATION

## Overview

This document explains how Semi_project2 works in detail, how the major components interact, how to operate the system correctly, and how to diagnose the failures that commonly occur in this VMware-based sandbox workflow.

Semi_project2 is not just a single web application. It is a three-part analysis system made of:

- a containerized application layer
- a Windows host-side VMware bridge
- a Windows guest VM with a guest agent

If any one of these three layers is incomplete or misconfigured, the system may appear to hang, fail to analyze, or return partial reports.

---

## 1. System Architecture

### 1.1 Application Layer

The application layer is responsible for:

- receiving uploads
- storing report records
- running static analysis
- selecting a VMware slot
- sending dynamic analysis jobs to the host bridge
- generating verdicts and scores
- rendering report views and downloadable artifacts

Primary project area:

```text
app/
```

This area contains the API routes, service logic, report generation, scoring rules, UI templates, and dynamic analysis orchestration.

### 1.2 Host Bridge Layer

The host bridge runs on the Windows host, outside Docker.

Its responsibilities are:

- reading bridge configuration
- locating `vmrun`
- locating the VMX file
- verifying snapshot availability
- checking bridge health
- creating job folders
- moving uploaded samples into shared inbox folders
- resetting the VM to a known snapshot
- starting the VM
- waiting for guest readiness
- collecting output from the guest outbox
- stopping the VM and cleaning up

Primary project area:

```text
host_bridge/
```

Main runtime pieces:

```text
host_bridge/host_bridge.py
host_bridge/workspace/
host_bridge/workspace/shared/
host_bridge/workspace/logs/
```

### 1.3 Guest VM Layer

The guest agent runs inside the Windows VM and is responsible for:

- writing heartbeat information
- checking shared folder readiness
- polling the inbox for jobs
- extracting sample contents
- deciding what files to execute and what files to skip
- launching supported files
- collecting runtime outputs
- writing `result.json` and artifacts into the outbox

Primary project area:

```text
guest_tools/
```

Important guest-side files:

```text
guest_tools/guest_agent.py
guest_tools/bootstrap_guest.ps1
```

---

## 2. End-to-End Analysis Flow

The full analysis flow is:

```text
User uploads sample
-> App stores upload
-> Static analysis starts
-> App asks bridge for a healthy/startable VM slot
-> Host bridge verifies VM path, snapshot, and shared folder
-> Host bridge reverts snapshot
-> Host bridge starts VM
-> Guest agent publishes fresh heartbeat
-> Bridge confirms guest readiness
-> Bridge writes job into shared inbox
-> Guest agent executes supported files
-> Guest agent writes result.json to shared outbox
-> Bridge reads result.json
-> App merges static + dynamic results
-> App writes final report
-> UI displays summary and detailed report
```

---

## 3. Repository Responsibilities by Directory

### 3.1 `app/`

This contains the application itself.

Typical responsibilities include:

- API routes
- static analysis logic
- report processing
- scoring and verdict logic
- report UI rendering
- bridge backend calls
- VMware slot coordination

Important subareas usually include:

```text
app/api/
app/services/
app/sandbox/
app/machinery/
app/ui/
```

### 3.2 `host_bridge/`

This contains the host-side bridge used on the Windows host.

It includes:

- bridge API server
- VMware control logic
- readiness checks
- snapshot handling
- bridge logs
- job and shared folder workspace

Important runtime directories:

```text
host_bridge/workspace/jobs/
host_bridge/workspace/logs/
host_bridge/workspace/shared/inbox/
host_bridge/workspace/shared/outbox/
host_bridge/workspace/state/
```

### 3.3 `guest_tools/`

This contains the Windows guest execution helpers.

It includes:

- guest bootstrap script
- guest agent
- scheduled task setup logic

---

## 4. Required Environment Assumptions

### 4.1 Host Assumptions

The host machine is expected to have:

- VMware Workstation installed
- Docker Desktop installed and working
- Python installed for running the host bridge
- access to the VMX file at the configured location

### 4.2 Guest VM Assumptions

The guest is expected to be:

- Windows 10 Pro x64
- stored directly at `C:\Win10x64`
- named `Win10x64`
- snapshot-enabled with snapshot `clean`
- configured with VMware shared folder name `shared`
- equipped with VMware Tools
- equipped with Visual C++ x64 and x86 redistributables
- equipped with Python 3.10 x64
- equipped with the guest agent scheduled task

Detailed VM preparation is described in:

- [README_VM.md](README_VM.md)

---

## 5. Path and Naming Rules

These defaults must match the project configuration unless you intentionally reconfigure every dependent setting.

### Required values

```text
VM Folder:      C:\Win10x64
VMX Path:       C:\Win10x64\Win10x64.vmx
VM Name:        Win10x64
Snapshot Name:  clean
Shared Name:    shared
```

### Important restriction

Do not use the default VMware path:

```text
C:\Users\<user>\Documents\Virtual Machines\Win10x64
```

unless you also update all matching configuration references. The project is typically prepared to expect the VM directly under `C:\`.

---

## 6. Configuration Files

### 6.1 Main `.env`

The application uses `.env` for app-level runtime configuration.

Typical values here affect:

- backend mode
- bridge URL
- analysis behavior
- timeout policy
- scoring thresholds

### 6.2 `scripts/host_bridge.env`

The host bridge uses this file for Windows host settings such as:

- `VMX_PATH`
- `VMRUN_PATH`
- `PYTHON_BIN`
- `BRIDGE_WORK_DIR`
- `BRIDGE_SHARED_DIR`
- `DEFAULT_VM_NAME`
- `DEFAULT_SNAPSHOT`
- timeouts

Typical expected bridge values:

```text
VMX_PATH=C:\Win10x64\Win10x64.vmx
DEFAULT_VM_NAME=Win10x64
DEFAULT_SNAPSHOT=clean
```

If these values do not match the real host environment, the bridge will fail or silently remain unhealthy.

---

## 7. Startup Procedure

### Step 1: Prepare the VM
Complete all setup steps in:

- [README_VM.md](README_VM.md)

Do not skip the clean snapshot creation.

### Step 2: Prepare environment files
Make sure `.env` and the bridge environment file both exist and point to real paths.

### Step 3: Start the bridge and app
Run:

```bat
run.bat
```

This normally launches the host bridge and then the Dockerized application.

### Step 4: Open the UI
Once startup completes, open the local web interface shown in the console.

### Step 5: Upload a sample
Use the upload UI to submit a supported sample.

---

## 8. Bridge Health and Slot Selection

Before dynamic analysis starts, the app checks bridge health and tries to find an available VMware slot.

The host bridge `/health` endpoint is used for this.

A typical manual check is:

```cmd
curl "http://localhost:9080/health?vm_name=Win10x64&snapshot_name=clean"
```

Important fields to inspect include:

- `vmrun_exists`
- `vmx_path`
- `snapshot_exists`
- `shared_dir_ready`
- `vm_running`
- `guest_ready`
- `guest_heartbeat`
- slot reason fields if your bridge version exposes them

### Healthy interpretation

A bridge slot is usable when:

- the VMX path is correct
- the snapshot exists
- the shared directory is ready
- the VM can be started and the guest can become ready

If the bridge logic has been updated correctly, a powered-off VM may still be considered startable even if the heartbeat is stale.

---

## 9. Shared Folder Contract

The shared folder is the file exchange contract between host and guest.

### Host-side expectation

The host bridge writes and reads through:

```text
host_bridge/workspace/shared
host_bridge/workspace/shared/inbox
host_bridge/workspace/shared/outbox
```

### Guest-side expectation

Inside the guest, this must resolve as VMware shared folder name:

```text
shared
```

and be visible as something equivalent to:

```cmd
dir "\\vmware-host\Shared Folders\shared"
```

If this contract is broken, the guest will not receive jobs or the bridge will never receive `result.json`.

---

## 10. Guest Agent Responsibilities in Detail

The guest agent is one of the most failure-prone components because it deals directly with hostile or malformed sample contents.

A correct guest agent must:

- publish heartbeat frequently
- verify shared folder readiness
- read new jobs from inbox
- extract archives carefully
- classify candidate files before launch
- skip unsupported or clearly invalid targets
- launch supported scripts or binaries in a controlled way
- avoid GUI-blocking behavior where possible
- collect outputs and runtime traces
- write a result file to outbox even when partial failures occur

### Desired execution policy

The guest agent should not equate:

```text
process created
```

with

```text
sample executed successfully
```

It should distinguish:

- attempted
- succeeded
- failed
- skipped

This matters especially for:

- fake DLL files
- fake PE files
- documents that open modal dialogs
- files without meaningful executable content

---

## 11. Snapshot Policy

The `clean` snapshot is the foundation of repeatability.

Create or recreate the snapshot only after all guest preparation is complete.

That means:

- VMware Tools installed
- security settings adjusted
- VC++ x64 and x86 installed
- Python installed
- guest agent copied and installed
- scheduled task confirmed
- heartbeat confirmed
- shared folder confirmed

If the snapshot is taken before these steps, every revert restores a broken guest.

### Best practice

Whenever anything guest-related changes:

```text
1. update the guest
2. verify the guest
3. restart the guest task if needed
4. create a fresh clean snapshot
```

---

## 12. Report Generation Model

Final reports are built by combining static and dynamic data.

### Static side contributes:
- file metadata
- archive structure
- strings
- YARA matches
- family hints
- keyword hits
- IOC extraction

### Dynamic side contributes:
- process launches
- dropped files
- stdout/stderr artifacts
- some network-related runtime traces
- sandbox execution evidence

### Final report sections usually include:
- verdict
- score
- key findings
- top evidence
- behavior summary
- IOC summary
- advanced details
- downloadable JSON and artifacts

---

## 13. Failure Cases and Fixes

### 13.1 `no_healthy_vm_slot`

**Typical meaning**  
The app asked for a usable bridge slot and the bridge refused all available VMs.

**Common causes**
- wrong VMX path
- snapshot missing
- shared folder mismatch
- stale heartbeat logic
- bad bridge health logic
- guest task not running

**What to check**
```cmd
curl "http://localhost:9080/health?vm_name=Win10x64&snapshot_name=clean"
```

Verify:
- `vmrun_exists`
- `snapshot_exists`
- `shared_dir_ready`
- heartbeat freshness
- startable slot logic

### 13.2 `vmrun start ... timed out`

**Typical meaning**  
The bridge tried to start the VM but `vmrun` did not return in time.

**Common causes**
- VM startup is too slow
- VMware Tools or guest environment is unstable
- popups block startup flow
- damaged or heavy snapshot
- `vmrun start` is waiting without GUI-safe behavior

**Fixes**
- verify snapshot health
- reduce guest startup burden
- confirm VMware Tools
- use `nogui` startup logic if supported
- verify there are no persistent modal dialogs inside the guest

### 13.3 Guest hangs on popup dialogs

**Typical meaning**  
The guest is launching a file that produces a modal dialog such as RunDLL failure, Open With, or an application error popup.

**Common causes**
- fake DLL launched by `rundll32`
- invalid EXE launched as real PE
- document types opened with GUI apps
- missing runtime dependencies
- inadequate guest preflight checks

**Fixes**
- preflight-check DLL and EXE formats
- skip invalid DLLs and fake PE files
- avoid launching GUI-only file types blindly
- add popup process termination rules where appropriate
- recreate the clean snapshot after guest agent changes

### 13.4 `dynamic_analysis_required_but_not_executed`

**Typical meaning**  
The policy requires dynamic behavior, but no supported file was actually executed successfully.

**Common causes**
- sample contains only unsupported files
- execution rules skipped everything
- guest agent failed before launch
- bridge never delivered the job correctly

**Fixes**
- inspect sample contents
- verify guest rules
- verify outbox result behavior
- verify shared folder handoff

### 13.5 Reports stay on `running` until manual refresh

**Typical meaning**  
The backend completed or failed, but the UI polling did not refresh state correctly.

**Common causes**
- insufficient client-side polling
- stale front-end state
- page only updates after reload

**Fixes**
- improve report polling
- refresh report status and list automatically
- update detail view once terminal state is reached

### 13.6 Heartbeat exists but slot is still unhealthy

**Typical meaning**  
The bridge can see heartbeat data, but still refuses the slot.

**Common causes**
- heartbeat path mismatch
- stale heartbeat
- shared folder name mismatch
- bridge logic requires guest_ready too early
- VM is powered off and stale heartbeat is incorrectly treated as fatal

**Fixes**
- inspect heartbeat contents
- confirm bridge and guest agree on shared folder name
- adjust slot logic so powered-off but startable VMs are not rejected immediately

---

## 14. Verification Commands

### 14.1 Host-side checks

Check VM path:

```cmd
dir C:\Win10x64
```

Check bridge health:

```cmd
curl "http://localhost:9080/health?vm_name=Win10x64&snapshot_name=clean"
```

Check bridge workspace:

```cmd
dir C:\Users\User\Downloads\Semi_project2-main\host_bridge\workspace
dir C:\Users\User\Downloads\Semi_project2-main\host_bridge\workspace\shared
dir C:\Users\User\Downloads\Semi_project2-main\host_bridge\workspace\shared\inbox
dir C:\Users\User\Downloads\Semi_project2-main\host_bridge\workspace\shared\outbox
```

Inspect heartbeat from host view:

```cmd
type C:\Users\User\Downloads\Semi_project2-main\host_bridge\workspace\shared\agent_heartbeat.json
```

### 14.2 Guest-side checks

Check scheduled task:

```powershell
Get-ScheduledTask -TaskName SandboxGuestAgent
```

Check sandbox work directory:

```cmd
dir C:\sandbox_work
```

Check shared folder visibility:

```cmd
dir "\\vmware-host\Shared Folders\shared"
```

Check the Python command line actually running:

```powershell
Get-CimInstance Win32_Process | where {$_.Name -eq "python.exe"} | select CommandLine
```

This confirms whether the running task is using the expected `guest_agent.py` path.

---

## 15. UI Notes

The report UI should prioritize readability.

Recommended display order:
- final verdict and score
- key findings
- top evidence
- behavior summary
- IOC summary
- advanced metrics
- raw artifacts and deep forensic tables lower on the page

Failure sections should only be shown when the report actually failed. Otherwise they create noise and confusion.

---

## 16. Maintenance Guidance

### When changing host-side code
Examples:
- bridge logic
- vm slot health
- UI rendering
- scoring
- report generation

Do:
- replace the host files
- restart the bridge
- restart the app stack if needed

### When changing guest-side code
Examples:
- guest agent launch rules
- popup handling
- preflight file checks
- heartbeat logic

Do:
- replace files in the guest
- restart the scheduled task
- verify heartbeat
- create a fresh `clean` snapshot

### When changing both host and guest
Do the host restart and guest snapshot workflow separately. Do not assume replacing files alone is enough.

---

## 17. Operational Best Practice

Treat the Windows guest as disposable.

That means:
- keep it minimal
- keep it deterministic
- keep a stable `clean` snapshot
- avoid installing unnecessary software
- snapshot only verified states
- rebuild or revert aggressively when behavior becomes inconsistent

A stable snapshot and a predictable guest agent matter more than adding extra tools inside the VM.

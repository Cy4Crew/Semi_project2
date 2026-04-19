# Semi_project2

Semi_project2 is a VMware-assisted malware analysis sandbox that combines static inspection, controlled Windows guest execution, IOC extraction, evidence scoring, and a browser-based reporting interface.

This project is intended to support repeatable malware sample inspection with a snapshot-based Windows VM workflow. Samples are uploaded through the web UI, analyzed statically, optionally executed inside an isolated guest, and converted into structured reports that summarize verdict, score, behavior, evidence, and extracted indicators.

---

## What This Project Does

Semi_project2 provides the following workflow:

1. Accept a sample upload from the web UI
2. Unpack and inspect the uploaded content
3. Perform static analysis on archive members and extracted files
4. Send supported files into a Windows guest through the VMware host bridge
5. Execute supported targets inside the VM
6. Collect runtime behavior such as:
   - process execution
   - dropped files
   - output artifacts
   - network-related traces
7. Merge static and dynamic evidence into a final report
8. Present the result in a structured UI and downloadable JSON

---

## Core Features

- Static analysis for uploaded samples and archive members
- Optional dynamic execution inside a resettable Windows VM
- VMware snapshot-based isolation
- Host-side bridge for VMware control and sample handoff
- Guest-side agent for heartbeat, execution, and result return
- IOC extraction including URLs, IPs, malware families, YARA, and file paths
- Evidence-based scoring and verdict classification
- Report UI with summary, evidence, behavior, IOC sections, and downloadable artifacts
- Optional Sysmon-based telemetry for process, network, file, and registry events
- Repeatable analysis flow using a `clean` snapshot

---

## Technology Stack

| Layer | Technology |
|---|---|
| API / Backend | Python, FastAPI |
| Frontend | HTML, CSS, JavaScript |
| Container Runtime | Docker Compose |
| Hypervisor Control | VMware Workstation, `vmrun` |
| Host Bridge | Python, FastAPI |
| Guest Runtime | Windows 10 Pro x64 VM, Python guest agent |

---

## Repository Structure

```text
app/                 Main application: API, services, UI, reports, scoring
guest_tools/         Guest-side agent and bootstrap script for the Windows VM
host_bridge/         Host-side VMware bridge and bridge workspace
scripts/             Startup helper scripts and environment loaders
docker-compose.yml   App container startup
run.bat              Main local startup entrypoint
README_VM.md         Windows VM installation and preparation guide
README_OPERATION.md  Detailed operational guide
README_SYSMON.md     Sysmon telemetry setup and integration guide
```

---

## High-Level Architecture

The system is split into three parts.

### 1. Application Layer
The containerized application accepts uploads, performs static analysis, coordinates dynamic analysis, calculates scores, and renders reports.

### 2. Host Bridge Layer
The host bridge runs on the Windows host machine, talks to VMware through `vmrun`, manages snapshot resets, controls VM startup and shutdown, and exchanges files with the guest through the shared folder.

### 3. Guest VM Layer
The guest agent runs inside the Windows VM, publishes heartbeat information, receives jobs from the host, executes supported files, collects runtime results, and writes the output back to the shared folder.

When Sysmon is enabled, the guest can also export structured telemetry such as process creation, network connections, DLL loads, file creation, and registry modifications.

---

## Expected VM Defaults

This project expects the VMware guest to follow these defaults unless configuration is changed consistently across the project.

```text
VM Folder:      C:\Win10x64
VMX Path:       C:\Win10x64\Win10x64.vmx
VM Name:        Win10x64
Snapshot Name:  clean
Shared Folder:  shared
Bridge Port:    9080
```

These defaults matter because the bridge and helper scripts are built around this path convention.

---

## Quick Start

### 1. Prepare the Windows VM
Before starting the project, prepare the guest VM completely.

See:

- [README_VM.md](README_VM.md)

### 2. Create Required Environment Files
Create the `.env` file and any other required environment configuration from the example files included in the project.

### 3. Start the Host Bridge and App
Run:

```bat
run.bat
```

This starts the host-side bridge and then starts the application stack.

### 4. Open the Web UI
Open the local address shown in the console output.

### 5. Upload a Sample
Use the web UI to upload a supported sample and review the generated report.

---

## Required VM Setup

The VMware guest is not optional when using the VMware bridge mode configured for this project.

The exact requirements for:

- VM storage location
- VM naming
- Windows edition
- required packages
- disabled security features
- shared folder configuration
- guest agent installation
- snapshot creation

are documented in:

- [README_VM.md](README_VM.md)

---

## Detailed Operations

For a full explanation of:

- startup flow
- host bridge behavior
- guest handoff
- report generation
- environment variables
- troubleshooting
- bridge failures
- snapshot policy
- maintenance workflow
- Sysmon telemetry deployment and event collection

see:

- [README_OPERATION.md](README_OPERATION.md)
- [README_SYSMON.md](README_SYSMON.md)

---

## Known Issues

- GUI-based or document-based samples may trigger blocking dialogs if the guest agent rules are outdated
- Invalid DLL or fake PE files can create misleading execution attempts if guest-side validation is weak
- Slow hosts may increase VMware startup time
- Re-enabling Defender, SmartScreen, Firewall, or UAC inside the guest can block analysis
- A snapshot taken before guest setup is complete will repeatedly restore a broken VM state
- Incorrect VM path or snapshot configuration can cause bridge health failures

---

## Best Practice

Whenever you change any of the following inside the guest:

- guest agent files
- Python environment
- Windows security settings
- Visual C++ runtime packages
- shared folder behavior
- scheduled task behavior

do this in order:

```text
1. Update the guest
2. Verify the guest works correctly
3. Restart the guest task if needed
4. Create a new clean snapshot
```

If you skip the final snapshot step, the bridge will continue restoring an outdated guest state.

---

## Notes

This README is intentionally concise and project-facing.

Use the following documents for the rest:

- VM setup: [README_VM.md](README_VM.md)
- full operation guide: [README_OPERATION.md](README_OPERATION.md)
- Sysmon telemetry guide: [README_SYSMON.md](README_SYSMON.md)

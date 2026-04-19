# README_SYSMON

## Overview

This document describes the Sysmon integration used by Semi_project2 to improve behavioral visibility during dynamic malware analysis inside the Windows guest VM.

When enabled, Sysmon telemetry is collected automatically during execution and exported into the analysis artifact JSON for later review.

---

## Implemented Components

### Sysmon Installation

Recommended path:

```text
C:\Tools\Sysmon\
```

Install Sysmon with network and image load monitoring enabled:

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmon_config.xml -n -l
```

### Configuration

The project uses a custom `sysmon_config.xml` with a broad collection policy.

Suggested baseline:

- Schema version 4.91
- `onmatch="exclude"` strategy
- Process, network, file, image load, and registry coverage

### Collector Module

`sysmon_collector.py` parses and normalizes selected event IDs:

| Event ID | Meaning |
|---|---|
| 1 | ProcessCreate |
| 3 | NetworkConnect |
| 7 | ImageLoad |
| 11 | FileCreate |
| 12 | Registry Create/Delete |
| 13 | Registry Value Set |

Noise filtering excludes common Windows background processes such as:

- `svchost.exe`
- `taskhostw.exe`

### guest_agent.py Workflow

During each analysis run:

1. Clear existing Sysmon logs
2. Execute the submitted sample
3. Read new Sysmon events
4. Parse and normalize results
5. Save to `result.json`

Example:

```json
{
  "sysmon_events": []
}
```

---

## Verified Output

The following telemetry was validated:

- Process launches
- Outbound connections
- DLL loading
- File creation
- Registry value changes

---

## Current Limitation

Sysmon data is currently stored in exported artifacts.  
If the web UI does not yet render `sysmon_events`, update the report page to expose this section.

---

## Recommended UI Additions

Add a telemetry tab or panel showing:

- Process tree
- Network destinations
- Dropped files
- Registry modifications
- Loaded modules

---

## Future Event IDs

Recommended next additions:

| Event ID | Meaning |
|---|---|
| 8 | CreateRemoteThread |
| 10 | ProcessAccess |
| 22 | DNSQuery |
| 23 | FileDelete |
| 25 | ProcessTampering |

---

## Operational Advice

After Windows updates or Sysmon version changes:

1. Re-apply configuration
2. Validate event generation
3. Confirm guest agent parsing
4. Recreate the clean snapshot

This keeps analysis results consistent and repeatable.
# Malware Sandbox Platform

A lightweight malware analysis sandbox that processes uploaded ZIP archives and produces evidence-based risk scores and verdicts.

---

## Overview

This system performs static and restricted dynamic analysis on uploaded samples.  
It extracts indicators, detects suspicious behavior patterns, and assigns a risk score with a final verdict.

---

## Key Features

- Secure ZIP upload and extraction (Zip Slip protection)
- Static analysis:
  - YARA rule matching
  - IOC extraction (IP, domain, URL, email)
  - Suspicious keyword detection
  - Obfuscation indicators
- Dynamic analysis (restricted environment):
  - Execution of supported file types
  - stdout / stderr capture
  - basic behavior tracing
- Risk scoring system with clear verdicts
- Web UI for browsing reports and evidence

---

## Quick Start

```bash
pip install -r requirements.txt
python run.py
```

---

## Docker

```bash
docker compose up --build
```

---

## API Endpoints

- `/` : Dashboard  
- `/api/samples/upload` : Upload sample  
- `/api/reports/` : List reports  
- `/api/reports/{id}` : JSON report  
- `/api/reports/{id}/view` : UI detail  
- `/api/reports/{id}/download` : Download result  

---

## Verdict Levels

- clean
- review
- suspicious
- malicious

---

## Documentation

For more details, see [README_OPERATIONS.md](./README_OPERATIONS.md)

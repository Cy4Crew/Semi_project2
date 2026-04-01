# Malware Sandbox Platform

A ZIP-based malware analysis demo system.  
Automates the process: Upload → Analyze → Score → Generate Report.

---

## Features

- ZIP file upload and validation
- Secure extraction (Zip Slip protection)
- Static analysis + basic dynamic execution
- Score-based malware classification
- Sample hashing (MD5 / SHA-1 / SHA-256)
- Reanalysis and evidence export
- Evidence-based result output
- JSON report download support

---

## Run

pip install -r requirements.txt
python run.py

---

## Docker

docker compose up --build

---

## API

- `/` : Dashboard
- `/api/samples/upload` : Upload sample
- `/api/reports/` : Report list
- `/api/reports/{id}` : JSON result
- `/api/reports/{id}/view` : Detail page
- `/api/reports/{id}/download` : Download


---

## Flow

Upload → Extract → Analyze → Score → Report → Export Evidence

---

For more details, see [README_OPERATIONS.md](./README_OPERATIONS.md)

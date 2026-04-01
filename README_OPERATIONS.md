# Malware Sandbox Platform - Operations Guide

This document explains system behavior and internal structure.

---

## 1. System Overview

The system analyzes uploaded ZIP files to determine whether they are malicious.

Workflow:

1. Upload ZIP
2. Validate and safely extract
3. Perform static analysis
4. Execute in restricted environment
5. Collect logs and behavior
6. Calculate score
7. Generate report

---

## 2. System Architecture

Components:

- API Server: Handles upload and query requests
- Worker: Executes analysis jobs
- Analyzer: Performs static and dynamic analysis
- Database: Stores job states and results

Data Flow:

Upload → API → Queue(DB) → Worker → Analyzer → DB → API Response

---

## 3. Database Overview

Main tables:

- samples: Uploaded file metadata
- reports: Analysis results
- trace_queue: Job queue consumed by workers

Note:
- Missing `trace_queue` causes worker failure

---

## 4. Security Controls

### Upload Restrictions
- Only ZIP files allowed
- Content-Type validation
- Max upload size limit
- Max file count limit
- Total extracted size limit

### ZIP Security
- Zip Slip protection
- Path validation enforced

---

## 5. Analysis Pipeline

### Static Analysis
- File structure inspection
- String extraction
- Suspicious pattern detection

### Dynamic Analysis
- Execution in restricted environment
- stdout / stderr collection
- Process monitoring
- Timeout handling

---

## 6. Scoring System

Score is calculated based on:

- Suspicious strings
- Execution results
- Behavior logs
- File structure

Output:
- Total score
- Detailed breakdown
- Key evidence

---

## 7. Report Lifecycle

queued → running → done / failed

---

## 8. API Details

POST /api/samples/upload

GET /api/reports/
GET /api/reports/{id}
GET /api/reports/{id}/view
GET /api/reports/{id}/download

---

## 9. Runtime Logs

- stdout
- stderr
- Process information
- Analysis logs
- Timeout status

---

## 10. Common Errors & Fixes

### 1. relation "trace_queue" does not exist

Cause:
- Database not initialized

Fix:
python -m app.init_db

---

### 2. Internal Server Error (JSON parse error)

Cause:
- API returns non-JSON response

Fix:
- Check Content-Type
- Validate response before JSON parsing

---

## 11. Execution Environment

Recommended: Docker

Run:

docker compose up --build

Details:
- API, DB, Worker separated
- Isolated execution environment

Warning:
- Running locally may execute malware
- Use isolated test environment

---

## 12. Execution Notes

- Not a full sandbox (lightweight environment)
- Use only test samples

---

## 13. Best Practice

- Always run in isolated environment
- Use Docker
- Block external network if possible


---

## 14. Verdict Policy

- 0-19: clean
- 20-39: review
- 40-69: suspicious
- 70-100: malicious

Reports also store MD5, SHA-1, and SHA-256 hashes for uploaded samples.


---

## Runtime Compatibility Note

- If `pefile` is unavailable, PE import inspection is skipped gracefully.
- If `yara-python` is unavailable, YARA matching is reported as unavailable instead of crashing the API.
- The Docker image installs `build-essential` so `yara-python` can build more reliably during image creation.

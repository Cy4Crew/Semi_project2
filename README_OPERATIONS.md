# Malware Sandbox Platform - Operations Guide

This document describes internal logic, analysis pipeline, scoring system, and debugging procedures.

---

## 1. System Pipeline

Upload  
→ Validation  
→ Safe Extraction  
→ Static Analysis  
→ Dynamic Analysis  
→ Scoring  
→ Report Generation

---

## 2. Static Analysis

The system analyzes each file for:

- Suspicious keywords (e.g., downloader, execution chains)
- YARA rule matches
- Indicators of Compromise (IOC)
- Obfuscation markers (encoding, entropy)
- PE import-based suspicious APIs
- Family/behavior hints

---

## 3. TXT Classification

TXT files are categorized to reduce false positives while preserving detection capability.

### Categories

- `plain_txt`  
  Generic text with no significant signals

- `descriptive_txt`  
  Documentation, README, or explanation content

- `log_txt`  
  Logs, debug output, or system traces

- `ioc_rich_txt`  
  Contains multiple indicators (IP, URL, domain)

- `ransom_note_txt`  
  Matches ransom note patterns:
  - "your files are encrypted"
  - "payment", "bitcoin", "private key"

- `script_like_txt`  
  Contains executable logic in text form:
  - PowerShell
  - cmd commands
  - downloaders (invoke-webrequest, downloadstring)

TXT files are not executable by default, but specific categories increase score.

---

## 4. Dynamic Analysis

Restricted execution environment:

- Only supported file types are executed
- Timeout enforced
- Captures:
  - stdout / stderr
  - file system changes
  - basic network traces

Unsupported runtimes fall back to static inspection.

---

## 5. Scoring Logic

Score is calculated from:

- Static signals
- YARA match count
- IOC count
- Obfuscation indicators
- Behavioral chains
- Runtime evidence

### Core Rules

- Plain text and documentation → low score
- IOC-heavy text → moderate score
- Ransom note text → elevated score
- Script-like text → elevated score
- Executable malware → high score

### Score Caps

To prevent false positives:

- Text-only bundles have upper bounds
- Exceptions:
  - `ransom_note_txt`
  - `script_like_txt`

These bypass strict caps and receive adjusted minimum scores.

---

## 6. Verdict Mapping

Typical mapping:

- 0–19 → clean
- 20–39 → review
- 40–69 → suspicious
- 70–100 → malicious

---

## 7. Debugging Guide

### If scores look incorrect:

Check:
- analyzed files
- tags (`plain_txt`, `script_like_txt`, etc.)
- YARA matches
- evidence reasons
- score breakdown

---

### Common Issues

**All files show same score**
- Score cap too aggressive
- Missing classification differentiation

**Benign files score too high**
- README/log not properly classified
- Test artifacts treated as malicious

**Malware scores too low**
- No executable content
- Missing runtime evidence
- Weak YARA/IOC signals

---

## 8. Key Inspection Points

Always review:

- score
- verdict
- evidence reasons
- analyzed files
- tags
- YARA matches

---

## 9. Notes

- This is not a full VM-based sandbox
- Intended for research and educational use
- Real malware analysis should be done in isolated environments

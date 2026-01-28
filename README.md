# FIM Ultimate – Red Team Edition

**FIM Ultimate** is a lightweight File Integrity Monitoring (FIM) tool written in Python. It was developed as a lab and learning project focusing on file integrity, alerting, and basic network-level visibility.

This project is **not intended as a production-ready security product**, but rather as a proof-of-concept for Red Team / Blue Team exercises and personal skill development.

---

## Overview

Traditional FIM tools focus only on filesystem changes. This project extends that idea by adding **optional network reporting logic** to simulate how integrity events might be exfiltrated in a real-world scenario.

For Red Team simulations, the tool includes simple techniques to make outbound traffic resemble normal browser activity. These features are intentionally basic and meant for controlled lab environments.

---

## Features

* **File Integrity Monitoring**
  Detects **new**, **modified**, and **deleted** files using SHA-256 hashing.

* **Baseline Management**
  Creates and stores filesystem snapshots (baselines) and compares future states against them.

* **Stealth Log Reporting (Lab Use)**

  * Basic User-Agent rotation (Chrome / Firefox / Edge)
  * Sends HTTP-based alerts that resemble normal browser traffic

* **VirusTotal Integration (Optional)**
  Queries file hashes against VirusTotal to check whether modified files are known malware.

* **Email Alerts**
  Sends SMTP notifications when integrity violations are detected.

* **Event Logging**
  All security-relevant actions are written to a local log file.

---

## Installation & Usage

### 1. Clone the Repository

```bash
git clone https://github.com/gokhvncan/python-fim-tool.git
cd python-fim-tool
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configuration

Edit `fim_tool.py` and update the following values if you want to enable optional features:

* `EMAIL_SENDER` / `EMAIL_PASSWORD` – SMTP alerting
* `VIRUSTOTAL_API_KEY` – Threat intelligence lookups

All features work independently; leaving placeholders unchanged will safely disable them.

### 4. Run the Tool

```bash
python fim_tool.py
```

---

## Project Structure

```text
python-fim-tool/
├── baselines/          # Stored hash databases
├── fim_tool.py         # Main script
├── requirements.txt    # Python dependencies
├── security_events.log # Local event logs
└── README.md           # Documentation
```

---

## Use Cases

* Red Team lab simulations
* Blue Team integrity monitoring practice
* SOC / DFIR learning environments
* Python security tooling practice

---

## Legal Disclaimer

This tool is provided **for educational and testing purposes only**.
It should be used **only in environments you own or have explicit permission to test**.

The author takes no responsibility for misuse or damage caused by this software.

---

Developed by **Gökhan Can**

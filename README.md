# 🛡️ FIM Ultimate - Python File Integrity Monitor

A lightweight, custom File Integrity Monitor (FIM) written in Python. It detects unauthorized file changes and integrates with **VirusTotal API** for threat intelligence.

## 🚀 Features
- **Real-time Integrity Checks:** Calculates SHA-256 hashes to detect modifications.
- **VirusTotal Integration:** Automatically scans modified files against VirusTotal database.
- **Email Alerts:** Sends instant SMTP notifications for critical alerts.
- **Baseline Management:** Creates and manages multiple security baselines.

## 🛠️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/gokhvncan/python-fim-tool.git](https://github.com/gokhvncan/python-fim-tool)
   cd python-fim-tool

2. **Install dependencies:**
   
Bash
pip install -r requirements.txt

Configuration: Open the python script and update the following placeholders with your credentials:

EMAIL_SENDER
EMAIL_PASSWORD (App Password)
VIRUSTOTAL_API_KEY

VIRUSTOTAL_API_KEY

Run the tool:

Bash
python fim_tool.py

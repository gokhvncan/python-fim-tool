# FIM Ultimate - Red Team Edition

**FIM Ultimate** is a lightweight and robust File Integrity Monitor (FIM) written in Python.

 **Red Team / NDR Update:** Unlike traditional FIM tools, this version includes **Network Detection & Response (NDR) Evasion** capabilities. It simulates legitimate browser traffic when reporting logs to bypass anomaly detection systems.

##  Features

- ** Real-time Integrity Checks:** Uses SHA-256 hashing to detect unauthorized file changes.
- ** NDR Evasion / Stealth Reporting;
- Uses **User-Agent Rotation** (Spoofing Chrome, Firefox, Edge). Simulates legitimate HTTP traffic to bypass firewall/NDR rules based on python-requests headers.
- ** VirusTotal Integration:** Automatically scans modified file hashes against the VirusTotal database.
- ** Email Alerts:** Sends immediate SMTP notifications for critical security events.
- ** Baseline Management:** Creates secure baselines and compares system state.

##  Installation & Usage

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/gokhvncan/python-fim-tool.git](https://github.com/gokhvncan/python-fim-tool.git)
   cd python-fim-tool

Install Dependencies

Bash
pip install -r requirements.txt
Configuration Open fim_tool.py and update:

EMAIL_SENDER / EMAIL_PASSWORD

VIRUSTOTAL_API_KEY

Run the Tool

Bash
python fim_tool.py
📂 Project Structure
Plaintext
python-fim-tool/
├── baselines/          # Stored hash databases
├── fim_tool.py         # Main script (Stealth Module Included)
├── requirements.txt    # Dependencies
├── security_events.log # Logs
└── README.md           # Documentation
⚠️ Legal Disclaimer
This tool is developed for educational, Red Team simulations, and defensive (Blue Team) purposes only.

Developed by Gökhan Can

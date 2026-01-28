# FIM Ultimate - Red Team Edition

**FIM Ultimate** is a lightweight and robust File Integrity Monitor (FIM) written in Python.

 **Red Team / NDR Update:** Unlike traditional FIM tools, this version includes **Network Detection & Response (NDR) Evasion** capabilities. It simulates legitimate browser traffic when reporting logs to bypass anomaly detection systems and firewalls.

##  Features

- ** Real-time Integrity Checks:** Uses SHA-256 hashing algorithms to detect unauthorized file changes immediately.
- ** NDR Evasion / Stealth Reporting:**
  - Uses **User-Agent Rotation** (Spoofing Chrome, Firefox, Edge) to mimic real users.
  - Simulates legitimate HTTP traffic to bypass firewall/NDR rules based on python-requests headers.
- ** VirusTotal Integration:** Automatically scans modified file hashes against the VirusTotal database for malware detection.
- ** Email Alerts:** Sends immediate SMTP notifications when a critical security event occurs.
- ** Baseline Management:** Creates secure baselines (snapshots) and compares the system state against them.

## 🛠️ Installation & Usage

### 1. Clone the Repository
Open your terminal and run the following commands:
```bash
git clone [https://github.com/gokhvncan/python-fim-tool.git](https://github.com/gokhvncan/python-fim-tool.git)
cd python-fim-tool
2. Install Dependencies
Install the required Python libraries:

Bash
pip install -r requirements.txt
3. Configuration
Open fim_tool.py in any text editor and update the following placeholders with your credentials:

EMAIL_SENDER / EMAIL_PASSWORD (For alerts)

VIRUSTOTAL_API_KEY (For threat intelligence)

4. Run the Tool
Bash
python fim_tool.py
📂 Project Structure
Plaintext
python-fim-tool/
├── baselines/          # Stored hash databases (Baselines)
├── fim_tool.py         # Main script (Stealth Module Included)
├── requirements.txt    # Python dependencies
├── security_events.log # Security event logs
└── README.md           # Project documentation
⚠️ Legal Disclaimer
This tool is developed for educational purposes, Red Team simulations, and defensive (Blue Team) testing only. The developer is not responsible for any misuse of this tool.

Developed by Gökhan Can

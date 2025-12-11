# 🛡️ FIM Ultimate - Python File Integrity Monitor

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**FIM Ultimate** is a lightweight and robust **File Integrity Monitor (FIM)** written in Python. It detects unauthorized file changes, provides threat intelligence via the **VirusTotal API**, and sends instant email notifications for critical security events.

## 🚀 Features
- **🔍 Real-time Integrity Checks:** Uses SHA-256 hashing algorithms to detect any file modifications.
- **🦠 VirusTotal Integration:** Automatically scans modified file hashes against the VirusTotal database for malware detection.
- **📧 Email Alerts:** Sends immediate SMTP notifications when a critical change or threat is detected.
- **📂 Baseline Management:** Creates secure baselines and continuously compares the system state against them.

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
Open the fim_tool.py script in any text editor and update the following placeholders with your credentials:

EMAIL_SENDER: Your sender Gmail address.

EMAIL_PASSWORD: Your Google App Password (Not your login password).

EMAIL_RECEIVER: The email address that will receive the alerts.

VIRUSTOTAL_API_KEY: Your free API key from VirusTotal.

4. Run the Tool
Bash

python fim_tool.py
📂 Project Structure
Plaintext

python-fim-tool/
├── baselines/          # Stored hash databases (Baselines)
├── fim_tool.py         # Main application script
├── requirements.txt    # Python dependencies
├── security_events.log # Security event logs
└── README.md           # Project documentation
⚠️ Legal Disclaimer
This tool is developed for educational and defensive (Blue Team) purposes only. The developer is not responsible for any misuse of this tool.

Developed by Gökhan Can

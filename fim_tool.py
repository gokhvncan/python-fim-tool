import hashlib
import os
import json
import time
import glob
import requests
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# --- CONFIG ---
BASELINES_DIR = "baselines"
LOG_FILE = "security_events.log"

# Email Config (Leave placeholders if not testing email)
EMAIL_SENDER = "YOUR_EMAIL_HERE"
EMAIL_PASSWORD = "YOUR_APP_PASSWORD_HERE"
EMAIL_RECEIVER = "RECEIVER_EMAIL_HERE"

# Threat Intel
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

# C2 Server for Exfiltration (Demo: Localhost)
C2_SERVER_URL = "http://127.0.0.1:8080/log_collector"

# CLI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def ensure_dirs():
    if not os.path.exists(BASELINES_DIR):
        os.makedirs(BASELINES_DIR)

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

# --- STEALTH MODULE (NDR EVASION) ---
def get_stealth_headers():
    # Rotates User-Agents to mimic legitimate browser traffic
    # Bypasses basic anomaly detection rules based on 'python-requests'
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    ]
    
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Connection': 'keep-alive'
    }
    
    # Add VT Key only if it's set
    if "YOUR_" not in VIRUSTOTAL_API_KEY:
        headers["x-apikey"] = VIRUSTOTAL_API_KEY
        
    return headers

def send_stealth_report_to_c2(message):
    # Mimics a browser posting data to a C2 server
    headers = get_stealth_headers()
    
    # Don't leak the API key to C2
    if "x-apikey" in headers:
        del headers["x-apikey"]

    try:
        # Short timeout to avoid hanging during demos
        requests.post(C2_SERVER_URL, json={"alert": message}, headers=headers, timeout=1)
    except:
        # Silent fail is intended for stealth tools
        pass

# --- ALERTS ---
def send_email_alert(message):
    if "YOUR_" in EMAIL_PASSWORD: return 

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = "🚨 SECURITY ALERT: Integrity Violation"
    
    body = f"Suspicious activity detected!\n\nDETAILS:\n{message}\n\nTimestamp: {datetime.now()}"
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print(f"{Colors.YELLOW}    [>] Email alert sent.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Email failed: {e}{Colors.RESET}")

def check_virustotal(file_hash):
    if "YOUR_" in VIRUSTOTAL_API_KEY: return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    # Use stealth headers to avoid being blocked by VT bot protection
    headers = get_stealth_headers()
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats['malicious']
        elif response.status_code == 404:
            return -1 # Unknown file
    except:
        return None
    return None

# --- CORE FUNCTIONS ---
def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

def create_baseline():
    ensure_dirs()
    target_folder = input(f"{Colors.BLUE}[?] Target Directory: {Colors.RESET}")
    if not os.path.isdir(target_folder):
        print(f"{Colors.RED}[!] Invalid directory.{Colors.RESET}")
        return

    session_name = input(f"{Colors.BLUE}[?] Session Name (default: baseline): {Colors.RESET}") or "baseline"
    print(f"\n{Colors.YELLOW}[*] Hashing files...{Colors.RESET}")
    
    files_data = {}
    for root, _, files in os.walk(target_folder):
        for file in files:
            filepath = os.path.join(root, file)
            f_hash = calculate_file_hash(filepath)
            if f_hash:
                files_data[filepath] = f_hash

    baseline_data = {
        "metadata": {"target": target_folder, "time": str(datetime.now())},
        "files": files_data
    }

    out_file = os.path.join(BASELINES_DIR, f"{session_name}.json")
    with open(out_file, "w") as f:
        json.dump(baseline_data, f, indent=4)

    print(f"{Colors.GREEN}[+] Baseline '{session_name}' saved.{Colors.RESET}")
    log_event(f"New baseline created for {target_folder}")

def monitor_integrity():
    ensure_dirs()
    baselines = glob.glob(os.path.join(BASELINES_DIR, "*.json"))
    
    if not baselines:
        print(f"{Colors.RED}[!] No baselines found. Create one first.{Colors.RESET}")
        return

    print(f"\n{Colors.HEADER}--- LOAD SESSION ---{Colors.RESET}")
    for i, f in enumerate(baselines):
        print(f"{i + 1}) {os.path.basename(f)}")
    
    try:
        sel = int(input(f"\n{Colors.BLUE}[?] Select ID: {Colors.RESET}")) - 1
        if sel < 0 or sel >= len(baselines): return
    except: return

    with open(baselines[sel], "r") as f:
        data = json.load(f)

    target_folder = data['metadata']['target']
    saved_hashes = data['files']
    
    print(f"\n{Colors.BLUE}[*] Monitoring started... (Stealth Mode: ON){Colors.RESET}")

    current_files = []
    issues = False
    
    # Helper to handle alerts
    def trigger(path, alert_type, f_hash=None):
        vt_info = ""
        vt_score = 0
        
        # VirusTotal Lookup
        if f_hash and "YOUR_" not in VIRUSTOTAL_API_KEY:
            print(f"{Colors.YELLOW}    [>] Querying VirusTotal...{Colors.RESET}", end="\r")
            vt_score = check_virustotal(f_hash)
            
            if vt_score is None: vt_info = " (VT: Error)"
            elif vt_score == -1: vt_info = " (VT: Unknown)"
            elif vt_score > 0: vt_info = f" (VT: ☣️ MALICIOUS: {vt_score}/70)"
            else: vt_info = " (VT: Clean)"
        
        msg = f"{alert_type}: {path}{vt_info}"
        
        # Determine Color
        color = Colors.RED + Colors.BOLD if (vt_score and vt_score > 0) else Colors.RED
        print(f"{color}[!!!] {msg}{Colors.RESET}")
        
        # SHOWCASE: Print the Spoofed Header for the Interview
        ua = get_stealth_headers()['User-Agent']
        print(f"{Colors.YELLOW}    [Stealth] Log exfiltrated using UA: {ua[:30]}...{Colors.RESET}")

        log_event(msg)
        send_email_alert(msg)
        send_stealth_report_to_c2(msg)
        return True

    # Check Existing & Modified
    for root, _, files in os.walk(target_folder):
        for file in files:
            path = os.path.join(root, file)
            current_files.append(path)
            
            if path not in saved_hashes:
                # NEW FILE
                f_hash = calculate_file_hash(path)
                issues = trigger(path, "NEW FILE", f_hash)
            else:
                # CHECK MODIFICATION
                f_hash = calculate_file_hash(path)
                if f_hash != saved_hashes[path]:
                    issues = trigger(path, "MODIFIED", f_hash)

    # Check Deleted
    for path in saved_hashes:
        if path not in current_files:
            issues = trigger(path, "DELETED")

    if not issues:
        print(f"\n{Colors.GREEN}[SAFE] System integrity verified.{Colors.RESET}")

if __name__ == "__main__":
    while True:
        print(f"\n{Colors.HEADER}=== FIM ULTIMATE (Red Team Edition) ==={Colors.RESET}")
        print("1) New Baseline")
        print("2) Start Monitor")
        print("3) Exit")
        
        choice = input(f"\n{Colors.BOLD}> {Colors.RESET}")
        
        if choice == "1": create_baseline()
        elif choice == "2": monitor_integrity()
        elif choice == "3": break

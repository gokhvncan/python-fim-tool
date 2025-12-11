import hashlib
import os
import json
import time
import glob
import requests
import smtplib 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# --- CONFIGURATION ---
BASELINES_DIR = "baselines"
LOG_FILE = "security_events.log"

# --- E-MAIL SETTINGS (FILL THESE) ---
EMAIL_SENDER = "YOUR_EMAIL_HERE"         # Example: myemail@gmail.com
EMAIL_PASSWORD = "YOUR_APP_PASSWORD_HERE" # Google App Password (Not your login password)
EMAIL_RECEIVER = "RECEIVER_EMAIL_HERE"   # Who will receive the alert?

# --- VIRUSTOTAL SETTINGS (FILL THIS) ---
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE" 

# --- COLORS ---
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
    formatted_message = f"[{timestamp}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(formatted_message + "\n")

# --- E-MAIL SENDER ---
def send_email_alert(message):
    # Prevents sending email if password is still the default placeholder
    if "YOUR_" in EMAIL_PASSWORD: 
        print(f"{Colors.YELLOW}[!] Email not sent. Please configure EMAIL_PASSWORD.{Colors.RESET}")
        return 

    subject = "🚨 SECURITY ALERT: File Integrity Compromised!"
    
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject
    
    body = f"""
    Suspicious activity detected on the system!
    
    DETAILS:
    {message}
    
    Time: {datetime.now()}
    This message was automatically sent by the Python File Integrity Monitor.
    """
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Standard SMTP settings for Gmail (Port 587)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls() # Encrypt connection
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, text)
        server.quit()
        print(f"{Colors.YELLOW}    [>] Email notification sent!{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Email sending error: {e}{Colors.RESET}")

# --- VIRUSTOTAL CHECK ---
def check_virustotal(file_hash):
    if "YOUR_" in VIRUSTOTAL_API_KEY: return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_resp = response.json()
            stats = json_resp['data']['attributes']['last_analysis_stats']
            return stats['malicious']
        elif response.status_code == 404:
            return -1
        else:
            return None
    except Exception:
        return None

def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def create_baseline():
    ensure_dirs()
    target_folder = input(f"{Colors.BLUE}[?] Enter directory path to scan: {Colors.RESET}")
    if not os.path.isdir(target_folder):
        print(f"{Colors.RED}[!] Error: Directory not found.{Colors.RESET}")
        return

    session_name = input(f"{Colors.BLUE}[?] Give this session a name: {Colors.RESET}") or "default"
    
    print(f"\n{Colors.YELLOW}[*] Scanning files...{Colors.RESET}")
    files_data = {}
    
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                files_data[filepath] = file_hash

    baseline_data = {
        "metadata": {"target_directory": target_folder, "timestamp": time.ctime()},
        "files": files_data
    }

    output_filename = os.path.join(BASELINES_DIR, f"{session_name}.json")
    with open(output_filename, "w") as f:
        json.dump(baseline_data, f, indent=4)

    print(f"\n{Colors.GREEN}[SUCCESS] Baseline saved!{Colors.RESET}")
    log_event(f"Baseline created for {target_folder}")

def monitor_integrity():
    ensure_dirs()
    baseline_files = glob.glob(os.path.join(BASELINES_DIR, "*.json"))
    
    if not baseline_files:
        print(f"{Colors.RED}[!] No baselines found.{Colors.RESET}")
        return

    print(f"\n{Colors.HEADER}--- AVAILABLE SESSIONS ---{Colors.RESET}")
    for index, file in enumerate(baseline_files):
        print(f"{index + 1}) {os.path.basename(file)}")
    
    try:
        selection = int(input(f"\n{Colors.BLUE}[?] Select session: {Colors.RESET}")) - 1
        if selection < 0 or selection >= len(baseline_files): return
    except ValueError: return

    selected_file = baseline_files[selection]
    with open(selected_file, "r") as f:
        data = json.load(f)

    target_folder = data['metadata']['target_directory']
    saved_hashes = data['files']
    
    print(f"\n{Colors.BLUE}[*] Monitoring started...{Colors.RESET}")

    issues_found = False
    current_files_on_disk = []
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            current_files_on_disk.append(os.path.join(root, file))

    def trigger_alert(filepath, alert_type, file_hash=None):
        vt_result = ""
        vt_score = 0
        
        # Only check VirusTotal if the API key is set
        if file_hash and "YOUR_" not in VIRUSTOTAL_API_KEY:
            print(f"{Colors.YELLOW}    [>] Checking VirusTotal...{Colors.RESET}", end="\r")
            vt_score = check_virustotal(file_hash)
            
            if vt_score is None: vt_result = " (VT: Error)"
            elif vt_score == -1: vt_result = " (VT: Unknown File)"
            elif vt_score > 0: vt_result = f" (VT: ☣️ MALICIOUS: {vt_score}/70)"
            else: vt_result = " (VT: Clean)"
        
        msg = f"{alert_type}: {filepath}{vt_result}"
        
        color = Colors.RED
        if vt_score and vt_score > 0:
            msg = f"☣️ VIRUS DETECTED! {msg}"
            color = Colors.RED + Colors.BOLD

        print(f"{color}[!!!] {msg}{Colors.RESET}")
        log_event(msg)
        
        # --- SEND EMAIL NOTIFICATION ---
        send_email_alert(msg)
        return True

    for filepath, original_hash in saved_hashes.items():
        if not os.path.exists(filepath):
            issues_found = trigger_alert(filepath, "FILE DELETED")
        else:
            current_hash = calculate_file_hash(filepath)
            if current_hash != original_hash:
                issues_found = trigger_alert(filepath, "FILE MODIFIED", current_hash)

    for filepath in current_files_on_disk:
        if filepath not in saved_hashes:
            current_hash = calculate_file_hash(filepath)
            issues_found = trigger_alert(filepath, "NEW FILE DETECTED", current_hash)

    if not issues_found:
        print(f"\n{Colors.GREEN}[SAFE] System is clean.{Colors.RESET}")

def show_banner():
    print(f"\n{Colors.HEADER}==================================================")
    print("   FIM ULTIMATE - EMAIL EDITION    ")
    print(f"=================================================={Colors.RESET}")

if __name__ == "__main__":
    while True:
        show_banner()
        print("A) Create Baseline")
        print("B) Monitor Integrity")
        print("Q) Quit")
        choice = input(f"\n{Colors.BOLD}Selection: {Colors.RESET}").upper()
        
        if choice == "A": create_baseline()
        elif choice == "B": monitor_integrity()
        elif choice == "Q": break
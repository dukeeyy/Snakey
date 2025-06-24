import os
import time
import json
import socket
import getpass
import hashlib
import platform
from datetime import datetime, timedelta, timezone
from requests import get, post
from pynput.keyboard import Key, Listener
from PIL import ImageGrab
import win32clipboard
from cryptography.fernet import Fernet
import requests
from elasticsearch import Elasticsearch, ConnectionError, TransportError, AuthenticationException
import pytz
import ssl
import shutil
import traceback # Added for detailed error logging


# === Configuration ===
base_path = "C:/Users/ktmdu/PycharmProjects/Snakey/Cryptography"
encrypted_path = os.path.join(base_path, "encrypted/")
os.makedirs(encrypted_path, exist_ok=True)

json_log_path = os.path.join(base_path, "snakey_log.json")
hash_ledger_path = os.path.join(base_path, "hash_ledger.json")
merkle_root_path = os.path.join(base_path, "merkle_root.txt")
wazuh_log_file = os.path.join(base_path, "wazuh_alerts.log")
daemon_log_file = os.path.join(base_path, "snakey_daemon_errors.log")

screenshot_information = "screenshot.png"  # Temporary screenshot file
key_path = os.path.join(encrypted_path, "key.key")
known_countries = ["Spain, Portugal"]

# === New: Country Change and VPN/Proxy IP Detection Configuration ===
last_country_path = os.path.join(base_path, "last_country.txt") # Path to store last country
KNOWN_VPN_IPS = {"89.214.145.78", "123.45.67.89"}

# === VirusTotal Config ===
VT_API_KEY = "c5f762cd3b75395566d2cce05125d25c40af4ac71ce73801e936080938784b46"
VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls/"
VT_FILE_LOOKUP = "https://www.virustotal.com/api/v3/files/"
VT_HEADER = {"x-apikey": VT_API_KEY}

# === Sensitive Command Detection Configuration ===
SENSITIVE_CMD_COMMANDS = [
    "format c:",  # Formatting drives
    "del /s /q",  # Force delete (subdirectories, quiet)
    "rmdir /s /q",  # Force remove directory (subdirectories, quiet)
    "net user",  # User management (info or creation)
    "net localgroup administrators",  # Admin group checks
    "taskkill /f /im",  # Force kill process by image name
    "schtasks /create",  # Create scheduled tasks (persistence)
    "reg delete",  # Delete registry keys
    "mimikatz",  # Credential dumping tool
    "certutil -urlcache -f -split",  # Common technique for downloading files
    "wmic shadowcopy delete",  # Delete volume shadow copies (often pre-ransomware)
    "vssadmin delete shadows",  # Delete volume shadow copies
    "powershell -nop -w hidden -c",  # Common PowerShell obfuscation for execution
    "invoke-expression",  # PowerShell alias for 'iex' - executes strings as commands
    "set-mppreference -disablerealtimemonitoring $true",  # Disable Windows Defender
    "bcdedit /set {current} safeboot network",  # Set network safe mode (persistence/bypass)
    "mshta.exe http",  # HTML Application (often for remote code execution)
    "bitsadmin /transfer",  # Download files via BITS
    "wevtutil cl system",  # Clear event logs
    "cipher /w",  # Overwrite free space (anti-forensics)
    "sdelete -z",  # Secure delete tool
]


# === Logging Function ===
def log_daemon_message(level, message):
    timestamp = datetime.now().isoformat()
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    try:
        with open(daemon_log_file, "a") as f:
            f.write(log_entry)
        print(log_entry.strip())
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to write to daemon log file: {e}")
        print(log_entry.strip())  # Still print even if file write fails


# === Encryption Key Loading ===
if not os.path.exists(key_path):
    log_daemon_message("ERROR", "Encryption key not found! Run GenerateKey.py first. Exiting.")
    exit(1)

try:
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    log_daemon_message("INFO", "Encryption key loaded successfully.")
except Exception as e:
    log_daemon_message("ERROR", f"Failed to load encryption key: {e}. Exiting.")
    exit(1)

# === Elasticsearch Configuration ===
ELASTIC_HOST = 'localhost'
ELASTIC_PORT = 9200
ELASTIC_USER = 'elastic'
ELASTIC_PASSWORD = 'vNODISLG+5Y0f*U4mKaI'

es_client = None

es_precheck_successful = False
log_daemon_message("INFO", "Performing basic requests.get pre-check to Elasticsearch endpoint.")
try:
    # Use verify=False here as well, consistent with Elasticsearch client config
    response = requests.get(f"https://{ELASTIC_HOST}:{ELASTIC_PORT}", auth=(ELASTIC_USER, ELASTIC_PASSWORD),
                            verify=False, timeout=10, stream=True)
    log_daemon_message("DEBUG", f"Basic requests.get status: {response.status_code}")
    # Read a byte to force connection establishment, then close to prevent hanging
    try:
        response.raw.read(1)
    except Exception as read_e:
        log_daemon_message("WARNING", f"Error reading from raw response during pre-check (might be expected for empty response): {read_e}")
    response.close()
    if response.status_code == 200:
        log_daemon_message("INFO", "Basic requests.get pre-check successful (status 200).")
        es_precheck_successful = True
    else:
        log_daemon_message("WARNING",
                           f"Basic requests.get pre-check returned non-200 status: {response.status_code}. Not proceeding with ES client init.")

except requests.exceptions.ConnectionError as e:
    log_daemon_message("ERROR",
                       f"requests.ConnectionError during pre-check: {e}. Possible firewall, service down, or wrong host/port.")
    traceback.print_exc() # Added traceback
except requests.exceptions.Timeout:
    log_daemon_message("ERROR", "requests.Timeout during pre-check: Connection timed out.")
    traceback.print_exc() # <-- Added traceback
except requests.exceptions.RequestException as e:
    log_daemon_message("ERROR",
                       f"requests.RequestException during pre-check: {e}. Could be SSL, authentication, or other request error.")
    traceback.print_exc() # Added traceback
except Exception as e:
    log_daemon_message("ERROR", f"Unexpected error during basic requests pre-check: {e}")
    traceback.print_exc() # <-- Added traceback

if es_precheck_successful:
    try:
        es_client = Elasticsearch(
            hosts=[f"https://{ELASTIC_HOST}:{ELASTIC_PORT}"],
            basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
            verify_certs=False,  # This disables SSL certificate verification
            ssl_show_warn=False, # Suppress SSL warnings in logs from elasticsearch client
            request_timeout=30 # Increased timeout for client initialization
        )
        # Attempt to ping to confirm full connection
        if es_client.ping():
            log_daemon_message("INFO", "Elasticsearch client initialized and connected successfully.")
        else:
            log_daemon_message("ERROR", "Elasticsearch client initialized but failed to ping the cluster. Check credentials.")
            es_client = None
    except ConnectionError as e:
        log_daemon_message("ERROR",
                           f"Elasticsearch Connection Error during client init: {e}. Check network, service status, firewall.")
        traceback.print_exc() # <-- Added traceback
        es_client = None
    except AuthenticationException as e:
        log_daemon_message("ERROR",
                           f"Elasticsearch Authentication Error during client init: {e}. Check ELASTIC_USER and ELASTIC_PASSWORD carefully.")
        traceback.print_exc() # <-- Added traceback
        es_client = None
    except TransportError as e:
        log_daemon_message("ERROR",
                           f"Elasticsearch Transport Error during client init (HTTP status {e.status_code}): {e.info}. Problem on ES server or request formatting.")
        traceback.print_exc() # <-- Added traceback
        es_client = None
    except Exception as e:
        log_daemon_message("ERROR", f"Unexpected error during Elasticsearch client initialization: {e}")
        traceback.print_exc() # <-- Added traceback
        es_client = None
else:
    log_daemon_message("WARNING", "Elasticsearch pre-check failed. Elasticsearch client will not be initialized.")


# === Utility Functions ===
def hash_file(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        log_daemon_message("ERROR", f"File not found for hashing: {filepath}")
        return None
    except Exception as e:
        log_daemon_message("ERROR", f"Hashing failed for {filepath}: {e}")
        return None


def hash_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def build_merkle_tree(hashes):
    if not hashes:
        return None
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])  # Duplicate last hash if odd number
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_hashes.append(hash_text(combined))
        hashes = new_hashes
    return hashes[0]


def vt_lookup_url(url):
    try:

        url_id = hashlib.sha256(url.encode()).hexdigest()
        response = requests.get(VT_URL_LOOKUP + url_id, headers=VT_HEADER, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            log_daemon_message("WARNING",
                               f"VirusTotal URL lookup failed (404 Not Found) for hash {url_id}. URL likely not previously analyzed by VT.")
        else:
            log_daemon_message("WARNING",
                               f"VirusTotal URL lookup failed with status {response.status_code} for {url}: {response.text}")
    except requests.exceptions.RequestException as e:
        log_daemon_message("ERROR", f"VT URL lookup failed: {e}")
    except Exception as e:
        log_daemon_message("ERROR", f"Unexpected error during VT URL lookup: {e}")
    return {}


def vt_lookup_file(file_path):
    try:
        if not os.path.exists(file_path):
            log_daemon_message("ERROR", f"File not found for VT lookup: {file_path}")
            return {}

        file_hash = hash_file(file_path)
        if not file_hash:  # If hashing failed
            return {}

        response = requests.get(VT_FILE_LOOKUP + file_hash, headers=VT_HEADER, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            log_daemon_message("WARNING",
                               f"VirusTotal File lookup failed (404 Not Found) for hash {file_hash} from {file_path}. File likely not previously analyzed by VT.")
        else:
            log_daemon_message("WARNING",
                               f"VirusTotal File lookup failed with status {response.status_code} for {file_path}: {response.text}")
    except requests.exceptions.RequestException as e:
        log_daemon_message("ERROR", f"VT File lookup failed: {e}")
    except Exception as e:
        log_daemon_message("ERROR", f"Unexpected error during VT File lookup: {e}")
    return {}


def check_important_directories():
    important_dirs = {
        "Desktop": os.path.join(os.path.expanduser("~"), "Desktop"),
        "Documents": os.path.join(os.path.expanduser("~"), "Documents"),
        "Downloads": os.path.join(os.path.expanduser("~"), "Downloads"),
        "AppData": os.environ.get("APPDATA", ""),
        "LocalAppData": os.environ.get("LOCALAPPDATA", "")
    }

    dir_status = {}
    for name, path in important_dirs.items():
        if os.path.exists(path):
            try:
                file_count = len(os.listdir(path))
                dir_status[name] = f"Found ({file_count} items)"
            except Exception as e:
                dir_status[name] = f"Error reading contents: {e}"
        else:
            dir_status[name] = "Not found"
    return dir_status


def check_stop_file():
    return os.path.exists(os.path.join(base_path, "stop_snakey.txt"))


def log_to_wazuh_file(data):
    try:
        # Ensure timestamp is string for JSON serialization
        if 'timestamp' in data and isinstance(data['timestamp'], datetime):
            data['timestamp'] = data['timestamp'].isoformat()
        with open(wazuh_log_file, "a") as f:
            f.write(json.dumps(data) + "\n")
        log_daemon_message("INFO", "Log written to Wazuh-compatible file.")
    except Exception as e:
        log_daemon_message("ERROR", f"Wazuh log file write failed: {e}")


def send_to_elasticsearch(data):
    global es_client
    if es_client:
        try:
            data_to_send = data.copy()
            # Ensure timestamp is ISO format for Elasticsearch
            if 'timestamp' in data_to_send and isinstance(data_to_send['timestamp'], datetime):
                data_to_send['timestamp'] = data_to_send['timestamp'].isoformat()

            # Ensure lists are not empty before sending for Kibana visualization
            if not data_to_send.get('alerts'):
                data_to_send['alerts'] = []  # Ensure it's an empty list if no alerts

            log_daemon_message("DEBUG",
                               f"Attempting to send log to Elasticsearch for timestamp: {data_to_send['timestamp']}")
            response = es_client.index(index="snakey_logs", document=data_to_send)
            log_daemon_message("SUCCESS", f"Log enviado para Elasticsearch. ID: {response['_id']}")
        except ConnectionError as e:
            log_daemon_message("ERROR",
                               f"Elasticsearch Connection Error during send: {e}. Check network, service status, firewall.")
            traceback.print_exc()
        except AuthenticationException as e:
            log_daemon_message("ERROR",
                               f"Elasticsearch Authentication Error during send: {e}. Check ELASTIC_USER and ELASTIC_PASSWORD.")
            traceback.print_exc()
        except TransportError as e:
            log_daemon_message("ERROR",
                               f"Elasticsearch Transport Error during send (HTTP status {e.status_code}): {e.info}. Problem on ES server or data format.")
            traceback.print_exc() # <-- Added traceback
        except Exception as e:
            log_daemon_message("ERROR", f"Falha inesperada ao enviar log para Elasticsearch: {e}")
            traceback.print_exc() # <-- Added traceback
    else:
        log_daemon_message("WARNING",
                           "Cliente Elasticsearch não está configurado ou conectado. O log não será enviado.")


# === Analyze Clipboard for Sensitive Commands ===
def analyze_clipboard_for_sensitive_commands(clipboard_content, alerts_list):
    """
    Analyzes clipboard content for predefined sensitive command patterns.
    Adds alerts to the alerts_list if matches are found.
    """
    if not clipboard_content or not isinstance(clipboard_content, str):
        return alerts_list

    normalized_clipboard = clipboard_content.lower().strip()

    for sensitive_cmd in SENSITIVE_CMD_COMMANDS:
        if sensitive_cmd.lower() in normalized_clipboard:
            alerts_list.append(
                f"Sensitive CMD command detected in clipboard: "
                f"'{clipboard_content[:100].replace('\n', ' ').strip()}...' (matched: '{sensitive_cmd}')"
            )


    return alerts_list

# === Check Country Change Function ===
def check_country_change(current_country, alerts_list):
    """
    Checks if the country has changed since the last recorded session.
    Stores the current country for future comparison.
    """
    try:
        if os.path.exists(last_country_path):
            with open(last_country_path, "r") as f:
                last_country = f.read().strip()
            if last_country and last_country != current_country:
                alerts_list.append(f"Country changed since last session: {last_country} -> {current_country}")
                log_daemon_message("ALERT", f"Country changed: {last_country} -> {current_country}")
        # Update the file for next session, even if it's the first run or country didn't change
        with open(last_country_path, "w") as f:
            f.write(current_country)
    except Exception as e:
        log_daemon_message("ERROR", f"Failed to check/update last country: {e}")
    return alerts_list

# === New: Check VPN/Proxy IP Function ===
def check_vpn_proxy_ip(current_ip, alerts_list):
    """
    Checks if the current public IP is in a list of known VPN/proxy IPs.
    """
    if current_ip in KNOWN_VPN_IPS:
        alerts_list.append(f"Access from known VPN/proxy IP: {current_ip}")
        log_daemon_message("ALERT", f"Access from known VPN/proxy IP detected: {current_ip}")
    return alerts_list


# === Main Log Collection Function ===
def collect_full_session():
    current_time = datetime.now(timezone.utc)  # consistent timestamping
    session_log = {
        "timestamp": current_time.isoformat(),  # consistent timestamp
        "system": {},
        "clipboard": "",
        "keystrokes": "",
        "screenshot_taken": False,
        "alerts": [],  # This list will be populated
        "virustotal": {},
        "important_dirs": {}
    }

    try:
        # System Info Collection
        session_log["system"]["username"] = getpass.getuser()
        hostname = socket.gethostname()
        session_log["system"]["hostname"] = hostname

        try:
            session_log["system"]["private_ip"] = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            session_log["system"]["private_ip"] = f"Error: {e}"
            session_log["alerts"].append(f"Could not get private IP: {e}")

        # Public IP and ISP lookup (includes country check and VPN/Proxy check)
        current_public_ip = None
        current_country = None

        ip_info = requests.get("https://ipinfo.io/json", timeout=5).json()
        session_log["system"]["public_ip"] = ip_info.get("ip")
        current_public_ip = ip_info.get("ip")
        session_log["system"]["country"] = ip_info.get("country")
        current_country = ip_info.get("country")
        session_log["system"]["region"] = ip_info.get("region")
        session_log["system"]["city"] = ip_info.get("city")
        session_log["system"]["isp"] = ip_info.get("org", "Unknown")

        # === Local time warning detection ===
        timezone_str = ip_info.get("timezone")
        if timezone_str:
            try:
                tz = pytz.timezone(timezone_str)
                local_time = datetime.now(tz)
                session_log["system"]["local_time"] = local_time.isoformat()
                if 0 <= local_time.hour < 5:
                    session_log["alerts"].append(
                        f"Unusual activity time: {local_time.strftime('%H:%M')} in {timezone_str}"
                    )
                    log_daemon_message(
                        "ALERT",
                        f"User active at {local_time.strftime('%H:%M')} in {timezone_str} (unusual hours)."
                    )
            except Exception as e:
                session_log["alerts"].append(f"Timezone parsing error: {e}")
                log_daemon_message("ERROR", f"Failed to calculate local time from timezone: {e}")
        else:
            session_log["alerts"].append("Could not determine timezone from IP.")
            log_daemon_message("WARNING", "Timezone not found in IP info.")

        if current_country and current_country not in known_countries:
            session_log["alerts"].append(f"Access from untrusted country: {current_country}")
            log_daemon_message("ALERT", f"Access from untrusted country: {current_country}")

        if current_country:
            session_log["alerts"] = check_country_change(current_country, session_log["alerts"])
        if current_public_ip:
            session_log["alerts"] = check_vpn_proxy_ip(current_public_ip, session_log["alerts"])

        session_log["system"]["processor"] = platform.processor()
        session_log["system"]["os"] = platform.system() + " " + platform.version()
        session_log["system"]["machine"] = platform.machine()

    except Exception as e:
        session_log["alerts"].append(f"System info error: {e}")
        log_daemon_message("ERROR", f"System info collection error: {e}")

    # Clipboard Collection and Analysis
    if platform.system() == "Windows":
        try:
            win32clipboard.OpenClipboard()
            try:
                clipboard_content = win32clipboard.GetClipboardData()
                session_log["clipboard"] = clipboard_content
            except TypeError:  # If clipboard is empty or non-text content
                session_log["clipboard"] = "Clipboard is empty or contains non-text data."
            win32clipboard.CloseClipboard()
            session_log["clipboard_hash"] = hash_text(session_log["clipboard"])

            # NEW: Analyze clipboard for sensitive commands
            session_log["alerts"] = analyze_clipboard_for_sensitive_commands(session_log["clipboard"], session_log["alerts"])

        except Exception as e:
            session_log["alerts"].append(f"Clipboard error: {e}")
            log_daemon_message("ERROR", f"Clipboard error: {e}")
    else:
        session_log["clipboard"] = "Clipboard collection not supported on this OS."
        session_log["clipboard_hash"] = hash_text(session_log["clipboard"])

    # Screenshot Collection and VT Scan
    screenshot_path = os.path.join(base_path, screenshot_information) # Define path here
    if platform.system() == "Windows":
        try:
            im = ImageGrab.grab()
            im.save(screenshot_path)
            session_log["screenshot_taken"] = True
            session_log["screenshot_hash"] = hash_file(screenshot_path)  # Hash of screenshot image file

            # VirusTotal Scan for screenshot
            vt_result = vt_lookup_file(screenshot_path)
            if vt_result:
                session_log["virustotal"]["screenshot_file"] = vt_result
                if vt_result.get("malicious", 0) > 0:
                    session_log["alerts"].append(
                        f"VirusTotal flagged screenshot file as malicious: {vt_result.get('malicious')} positives.")
                    log_daemon_message("ALERT", f"VT flagged screenshot as malicious: {vt_result.get('malicious')} positives.")
            else:
                log_daemon_message("INFO", "No VirusTotal result for screenshot or scan failed.")

        except Exception as e:
            session_log["alerts"].append(f"Screenshot error: {e}")
            log_daemon_message("ERROR", f"Screenshot error: {e}")
        finally:
            # Clean up the temporary screenshot file
            if os.path.exists(screenshot_path):
                try:
                    os.remove(screenshot_path)
                    log_daemon_message("DEBUG", f"Removed temporary screenshot file: {screenshot_path}")
                except Exception as e:
                    log_daemon_message("ERROR", f"Failed to remove temporary screenshot file: {e}")
    else:
        session_log["screenshot_taken"] = False
        session_log["alerts"].append("Screenshot collection not supported on this OS.")

    # VirusTotal Scan for Clipboard URL (if applicable)
    # Ensure clipboard is a string before checking .startswith()
    if isinstance(session_log["clipboard"], str) and session_log["clipboard"].strip().lower().startswith("http"):
        vt_result = vt_lookup_url(session_log["clipboard"])
        if vt_result:
            session_log["virustotal"]["clipboard_url"] = vt_result
            if vt_result.get("malicious", 0) > 0:
                session_log["alerts"].append(
                    f"VirusTotal flagged clipboard URL as malicious: {vt_result.get('malicious')} positives.")
                log_daemon_message("ALERT", f"VT flagged clipboard URL as malicious: {vt_result.get('malicious')} positives.")
        else:
            log_daemon_message("INFO", "No VirusTotal result for clipboard URL or scan failed.")

    # Keylogger
    keys = []

    def on_press(key):
        nonlocal keys
        try:
            if hasattr(key, 'char') and key.char is not None:
                keys.append(key.char)
            elif key == Key.space:
                keys.append(' ')
            elif key == Key.enter:
                keys.append('[ENTER]')
            elif key == Key.backspace:
                keys.append('[BACKSPACE]')
            elif key == Key.tab:
                keys.append('[TAB]')
            else:
                keys.append(f"[{str(key).replace('Key.', '')}]")
        except Exception as e:
            log_daemon_message("ERROR", f"Error in on_press keylogger: {e}")

    log_daemon_message("INFO", "Keylogger running. Create 'stop_snakey.txt' to terminate earlier.")
    listener = None
    try:
        with Listener(on_press=on_press) as listener:
            start_time = time.time()
            while time.time() - start_time < 143:  # Collect keystrokes for 2 mins and 23 secs
                time.sleep(0.5)  # Sleep for shorter intervals to check stop file more often
                if check_stop_file():
                    log_daemon_message("INFO", "Stop file detected. Exiting keylogger.")
                    break
            listener.stop()
            log_daemon_message("INFO", "Keylogger session completed.")
    except Exception as e:
        log_daemon_message("ERROR",
                           f"Keylogger listener error: {e}. This might happen if not running in a desktop session or permissions issue.")
        if listener:  # Attempt to stop listener cleanly even on error
            try:
                listener.stop()
            except Exception as stop_e:
                log_daemon_message("WARNING", f"Error stopping keylogger listener: {stop_e}")

    session_log["keystrokes"] = ''.join(keys)

    # Important Directories Check
    session_log["important_dirs"] = check_important_directories()

    # Before proceeding, we have to ensure alerts list is not None (shouldn't be, but as a safeguard)
    if session_log["alerts"] is None:
        session_log["alerts"] = []



    # This hash acts as an internal integrity check within the log itself
    log_string_for_internal_hash = json.dumps(session_log, sort_keys=True, default=str)
    session_log["_raw_log_hash"] = hash_text(log_string_for_internal_hash)  # Store hash of raw log inside

    #  Encrypt the entire session log
    try:
        encrypted_log_data = fernet.encrypt(log_string_for_internal_hash.encode('utf-8'))

        #  Define unique filename for encrypted log file
        encrypted_filename = f"log_{current_time.strftime('%Y%m%d_%H%M%S_%f')}.enc"
        full_encrypted_filepath = os.path.join(encrypted_path, encrypted_filename)

        #  Save the encrypted log to a file
        with open(full_encrypted_filepath, "wb") as f_enc:
            f_enc.write(encrypted_log_data)
        log_daemon_message("SUCCESS", f"Encrypted log saved to: {full_encrypted_filepath}")

        #  Hash the encrypted file content (for the blockchain ledger)
        encrypted_file_hash = hash_file(full_encrypted_filepath)
        if not encrypted_file_hash:
            log_daemon_message("ERROR", "Failed to hash encrypted log file. Ledger will not be updated with this log.")
            return session_log  # Exit without updating ledger for this log

        #  Update the blockchain-style hash ledger with the encrypted file's hash
        try:
            ledger = []
            if os.path.exists(hash_ledger_path):
                try:
                    with open(hash_ledger_path, "r") as f:
                        ledger = json.load(f)
                    # Convert legacy format if needed
                    if ledger and isinstance(ledger[0], str):  # Check if old format (list of hashes)
                        log_daemon_message("INFO", "Converting legacy hash ledger format to new dict format.")
                        converted_ledger = []
                        prev_h = "0" * 64
                        for h in ledger:
                            converted_ledger.append({
                                "timestamp": current_time.isoformat(),
                                # Cannot determine true timestamp for old entries
                                "encrypted_file_hash": h,
                                "previous_encrypted_file_hash": prev_h,
                                "chained_hash": hash_text(h + prev_h),
                                "encrypted_filepath": "legacy_path_unknown"
                            })
                            prev_h = h
                        ledger = converted_ledger
                        log_daemon_message("SUCCESS", "Legacy hash ledger converted.")
                except json.JSONDecodeError:
                    log_daemon_message("WARNING", "Existing hash ledger file is corrupt. Starting with empty ledger.")
                    ledger = []
            else:
                ledger = []

            try:
                previous_encrypted_file_hash = ledger[-1].get("encrypted_file_hash", "0" * 64) if ledger else "0" * 64
            except Exception as e:
                log_daemon_message("ERROR", f"Ledger appears malformed. Could not read last encrypted_file_hash: {e}")
                previous_encrypted_file_hash = "0" * 64

            chained_hash_input = encrypted_file_hash + previous_encrypted_file_hash
            chained_hash = hash_text(chained_hash_input)

            ledger_entry = {
                "timestamp": current_time.isoformat(),
                "encrypted_file_hash": encrypted_file_hash,
                "previous_encrypted_file_hash": previous_encrypted_file_hash,
                "chained_hash": chained_hash,
                "encrypted_filepath": full_encrypted_filepath  # Store the path to the encrypted log
            }

            ledger.append(ledger_entry)

            with open(hash_ledger_path, "w") as f:
                json.dump(ledger, f, indent=4)

            log_daemon_message("SUCCESS", "Blockchain-style hash ledger updated with encrypted log hash.")

            # 7. Update Merkle Root
            hash_list_for_merkle = [entry["encrypted_file_hash"] for entry in ledger if "encrypted_file_hash" in entry]
            merkle_root = build_merkle_tree(hash_list_for_merkle)

            with open(merkle_root_path, "w") as f:
                f.write(merkle_root)

            log_daemon_message("SUCCESS", "Merkle root saved (based on encrypted file hashes).")

        except Exception as e:
            log_daemon_message("ERROR", f"Failed to update hash ledger or Merkle root: {e}")

    except Exception as e:
        session_log["alerts"].append(f"Encryption or encrypted file save error: {e}")
        log_daemon_message("ERROR", f"Encryption or encrypted file save error: {e}")

    # Return the session_log for Elasticsearch (containing clear-text data for these)
    return session_log


# === Main Daemon Loop ===
if __name__ == "__main__":

    log_daemon_message("INFO", "Starting Snakey in daemon mode...")

    # Initial check for stop file in case it exists from a previous run
    stop_file_path = os.path.join(base_path, "stop_snakey.txt")
    if os.path.exists(stop_file_path):
        log_daemon_message("INFO", "Found existing 'stop_snakey.txt'. Removing it to start cleanly.")
        try:
            os.remove(stop_file_path)
        except Exception as e:
            log_daemon_message("ERROR", f"Failed to remove existing stop file: {e}")

    while True:
        if check_stop_file():
            log_daemon_message("INFO", "Snakey terminated by stop file.")
            break

        session_log = collect_full_session()


        log_to_wazuh_file(session_log)
        send_to_elasticsearch(session_log)

        log_daemon_message("INFO", f"Sleeping for 1 second before next collection at {datetime.now().isoformat()}...")
        time.sleep(1)

    # Final cleanup of stop file
    if os.path.exists(stop_file_path):
        try:
            os.remove(stop_file_path)
            log_daemon_message("INFO", "Stop file removed on graceful exit.")
        except Exception as e:
            log_daemon_message("ERROR", f"Failed to remove stop file during exit: {e}")
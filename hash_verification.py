import json
import hashlib
import os

# Path to your ledger JSON file
LEDGER_PATH = "C:\\Users\\ktmdu\\PycharmProjects\\Snakey\\Cryptography\\hash_ledger.json"  # Change this to your actual ledger path

def sha256_hash_file(filepath):
    """Compute SHA-256 hash of the file content."""
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def verify_latest_record(ledger_path):
    # Load ledger JSON
    with open(ledger_path, "r") as file:
        ledger = json.load(file)

    # Get the latest record (assuming ledger is a list)
    latest_record = ledger[-1]

    # Extract file path and stored hash
    encrypted_filepath = latest_record.get("encrypted_filepath")
    stored_hash = latest_record.get("encrypted_file_hash")

    if not encrypted_filepath or not stored_hash:
        print("Ledger record missing required fields.")
        return

    # Check if file exists
    if not os.path.isfile(encrypted_filepath):
        print(f"Encrypted file does not exist: {encrypted_filepath}")
        return

    # Compute hash of the file
    computed_hash = sha256_hash_file(encrypted_filepath)

    print(f"Stored hash:   {stored_hash}")
    print(f"Computed hash: {computed_hash}")

    # Compare hashes
    if computed_hash == stored_hash:
        print("Verification SUCCESS: The file matches the stored hash.")
    else:
        print("Verification FAILURE: The file does NOT match the stored hash.")

if __name__ == "__main__":
    verify_latest_record(LEDGER_PATH)

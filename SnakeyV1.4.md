 Snakey Integrity & Blockchain-style Ledger System



To enhance **log integrity, non-repudiation, and tamper detection**, we introduced cryptographic **SHA-256 hashing** and a **blockchain-style hash ledger** into Snakey.

This system ensures that:
- Each session log is hashed individually (`log_hash`).
- Each log hash is chained to the previous one (`chained_hash`) in a separate `hash_ledger.json`.
- Critical Snakey files are hashed and recorded for future integrity checks.

---

## New Features

### 1. `log_hash` in Every Session

Each `session_log` dictionary is hashed before being saved to disk:

```python
log_string = json.dumps(session_log, sort_keys=True)
session_log["log_hash"] = hash_text(log_string)
This allows verification of whether a log was modified after creation.

2. Blockchain-style Hash Ledger
Each log hash is linked to the previous one via:

python
Copy
Edit
chained_hash_input = session_log["log_hash"] + previous_hash
chained_hash = hash_text(chained_hash_input)
All chained hashes are saved in hash_ledger.json in the following format:

json
Copy
Edit
{
  "timestamp": "2025-04-16T20:15:01",
  "log_hash": "d2f3...abcd",
  "previous_hash": "0e23...4567",
  "chained_hash": "598a...9fda"
}
This chaining enables log integrity verification across time. If any single log is changed, the hash chain breaks.

3. Critical File Integrity Check
The following files are hashed during each execution:

Snakey.py (main script)

key.key (encryption key)

snakey_log.json (log history)

hash_ledger.json (ledger file)

Hash results are stored under:

python
Copy
Edit
session_log["integrity"] = {
  "Script": {"path": "...", "sha256": "..."},
  "Encryption Key": {...},
  ...
}
If a file is missing or altered, an alert is appended to the log:

python
Copy
Edit
session_log["alerts"].append("[INTEGRITY] Encryption Key missing or tampered.")

Functions Added
python
Copy
Edit
def hash_file(filepath):
    """Returns SHA-256 hash of a file's contents."""
    ...

def hash_text(text):
    """Returns SHA-256 hash of a given string."""
    ...

 New Artifacts

File	Purpose
hash_ledger.json	Stores all chained hash entries
log_hash (in JSON)	Embedded log hash per session
integrity field	Stores hashes of Snakey's core files

 Benefits
 Tamper detection for logs and core Snakey components

Blockchain-like trust model for insider threat forensics

 No external dependencies (uses hashlib)

✅ Alerts raised automatically on suspicious changes


import os, json, base64, re, getpass
from collections import Counter, defaultdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

LOG_DIR = "logs"
LOG_PATH = LOG_DIR + "/encrypted_logs.jl"
SALT_PATH = LOG_DIR + "/key_salt.bin"

OUT_DIR = "out"
SUMMARY_ALERTS = f"{OUT_DIR}/summary_alerts.jsonl"
SUMMARY_REPORT = f"{OUT_DIR}/summary_report.txt"

os.makedirs(OUT_DIR, exist_ok=True)

def derive_key(passphrase, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode())

def decrypt_entry(aesgcm, entry):
    iv  = base64.b64decode(entry["iv"])
    tag = base64.b64decode(entry["tag"])
    ct  = base64.b64decode(entry["ct"])
    pt  = aesgcm.decrypt(iv, ct + tag, None)
    return json.loads(pt.decode())

# ---------------- Detection Patterns ---------------- #

PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|drop|sleep\(|or\s+1=1|--)", re.IGNORECASE),
    "XSS":            re.compile(r"(<script|onerror|onload|<img|javascript:)", re.IGNORECASE),
    "Brute Force":    re.compile(r"(wrong\d+|password=|login failed)", re.IGNORECASE),
    "LFI":            re.compile(r"(etc/passwd|boot.ini|php://filter|\.\./)", re.IGNORECASE),
    "RFI":            re.compile(r"(http://|https://).*\.php", re.IGNORECASE),
    "Admin Scan":     re.compile(r"(/admin|wp-admin|wp-login\.php|phpmyadmin)", re.IGNORECASE),
    "Scanner/Bot":    re.compile(r"(sqlmap|nmap|nikto|curl|bot)", re.IGNORECASE),
}

print("=== Encrypted Log Analyzer (Clean Output) ===")
passphrase = getpass.getpass("Enter passphrase: ")

if not os.path.exists(SALT_PATH):
    print("Salt missing! Cannot decrypt.")
    exit()

with open(SALT_PATH, "rb") as f:
    salt = f.read()

key = derive_key(passphrase, salt)
aesgcm = AESGCM(key)

# Counters
attack_count = Counter()
ip_count = Counter()
alerts = []

print("\nAnalyzing logs...\n")

with open(LOG_PATH, "r") as f:
    for line in f:
        try:
            entry = json.loads(line)
            dec = decrypt_entry(aesgcm, entry)

            ip   = dec.get("ip", "unknown")
            path = dec.get("path", "")
            text = json.dumps(dec)

            ip_count[ip] += 1

            # Pattern matching
            found_attack = None
            for attack_type, regex in PATTERNS.items():
                if regex.search(text) or regex.search(path):
                    found_attack = attack_type
                    break

            if found_attack:
                attack_count[found_attack] += 1

                alert = {
                    "ip": ip,
                    "attack": found_attack,
                    "path": path
                }
                alerts.append(alert)

                print(f"[{found_attack}] from {ip} → {path}")

        except Exception:
            pass

# ---------------- SUMMARY OUTPUT ---------------- #

print("\n=== FINAL SUMMARY ===")

with open(SUMMARY_REPORT, "w") as rep:
    rep.write("=== FINAL SUMMARY ===\n")

    for attack, count in attack_count.items():
        print(f"{attack}: {count}")
        rep.write(f"{attack}: {count}\n")

    print("\nTop IPs:")
    rep.write("\nTop IPs:\n")

    for ip, count in ip_count.most_common(10):
        print(f"{ip}: {count} requests")
        rep.write(f"{ip}: {count} requests\n")

# Save alerts file
with open(SUMMARY_ALERTS, "w") as f:
    for alert in alerts:
        f.write(json.dumps(alert) + "\n")

print("\nSummary saved to:", SUMMARY_REPORT)
print("Alerts saved to:  ", SUMMARY_ALERTS)
print("\nAnalysis complete.\n")

           

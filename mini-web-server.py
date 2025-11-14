
import os
import json
import base64
import time
import getpass
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# Configuration
# -------------------------
LOG_DIR = "logs"
SALT_PATH = os.path.join(LOG_DIR, "key_salt.bin")
LOG_PATH = os.path.join(LOG_DIR, "encrypted_logs.jl")
SALT_SIZE = 16  # bytes
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # 32 bytes => AES-256
NONCE_SIZE = 12  # AES-GCM recommended nonce size

# Make logs dir
os.makedirs(LOG_DIR, exist_ok=True)

# Ensure salt file exists or create one (first run)
def get_or_create_salt(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            s = f.read()
            if len(s) != SALT_SIZE:
                raise RuntimeError("Invalid salt size in " + path)
            return s
    else:
        salt = os.urandom(SALT_SIZE)
        # write salt with restrictive permissions
        with open(path, "wb") as f:
            f.write(salt)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return salt

# Derive key from passphrase using scrypt and the persistent salt
def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, backend=default_backend())
    return kdf.derive(passphrase.encode("utf-8"))

# AES-GCM helper: encrypt structured bytes -> dict with iv, ct, tag (base64 encoded)
def encrypt_bytes(aesgcm: AESGCM, plaintext: bytes) -> dict:
    iv = os.urandom(NONCE_SIZE)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, associated_data=None)  # returns ciphertext||tag
    tag = ct_with_tag[-16:]
    ciphertext = ct_with_tag[:-16]
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ct": base64.b64encode(ciphertext).decode("utf-8")
    }

# Atomic append to encrypted log file (binary)
def append_encrypted_entry(path: str, entry: dict):
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    data = line.encode("utf-8")
    # Append and fsync to ensure durability
    with open(path, "ab") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            # fsync may not be available on some platforms (like certain Windows setups)
            pass

# -------------------------
# Start-up: ask user for passphrase & derive key
# -------------------------
print("Mini Web Server (logs encrypted at rest).")
print("Enter passphrase to derive AES-256 key. Keep the same passphrase for decryption later.")
passphrase = getpass.getpass("Passphrase: ").strip()
if not passphrase:
    print("Passphrase cannot be empty. Exiting.")
    raise SystemExit(1)

salt = get_or_create_salt(SALT_PATH)
try:
    key = derive_key_from_passphrase(passphrase, salt)
except Exception as e:
    print("Key derivation failed:", e)
    raise

aesgcm = AESGCM(key)
# zeroing variables like passphrase is not guaranteed, but we can delete reference
del passphrase
del key

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)

# Helper: build structured log dict from request & response info
def build_log_record(req, resp_status: int, resp_size: int):
    # Capture commonly useful fields. Avoid logging huge bodies.
    try:
        body_bytes = req.get_data() or b""
    except Exception:
        body_bytes = b""
    # limit body size logged
    body_snippet = body_bytes[:1024]  # first 1KB only
    try:
        body_text = body_snippet.decode("utf-8", errors="replace")
    except Exception:
        body_text = "<binary>"
    record = {
        "ip": req.headers.get("X-Forwarded-For", req.remote_addr or "-"),
        "method": req.method,
        "path": req.full_path[:-1] if req.full_path.endswith("?") else req.full_path,
        "protocol": req.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        "status": resp_status,
        "size": resp_size,
        "referer": req.headers.get("Referer", "-"),
        "user_agent": req.headers.get("User-Agent", "-"),
        "ts": datetime.now(timezone.utc).isoformat(),
        # include some request parameters and a body snippet for detection (beware of sensitive data)
        "args": req.args.to_dict(flat=False),
        "form": req.form.to_dict(flat=False),
        "json": None,
        "body_snippet": body_text
    }
    # try parse json body if present
    try:
        j = req.get_json(silent=True)
        if j is not None:
            record["json"] = j
    except Exception:
        record["json"] = None
    return record

# after_request: create structured record, encrypt, append to file
@app.after_request
def after_request_handler(resp):
    try:
        status = getattr(resp, "status_code", 200)
        size = resp.calculate_content_length() or 0
        rec = build_log_record(request, status, size)
        # Convert structured record to bytes and encrypt
        plaintext = json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        enc_entry = encrypt_bytes(aesgcm, plaintext)
        append_encrypted_entry(LOG_PATH, enc_entry)
    except Exception as e:
        # Do NOT propagate logging errors to client; just print server-side
        print("Logging/encryption error:", e)
    return resp

# Routes (same functionality as your original)
@app.route("/")
def home():
    return "OK"

@app.route("/login.php", methods=["GET", "POST"])
def login():
    # echo back params to simulate application behavior
    # We intentionally do not log plaintext here; encryption happens in after_request
    return jsonify({"msg": "login", "args": request.args, "form": request.form})

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"results": [], "q": q})

@app.route("/admin")
def admin():
    return ("forbidden", 403)

# Optional simple endpoint to show a small server status (does not reveal logs)
@app.route("/_status")
def status():
    return jsonify({"status": "running", "time": datetime.now(timezone.utc).isoformat()})

# -------------------------
# Run server
# -------------------------
if __name__ == "__main__":
    # Flask's built-in server is fine for lab testing. For more concurrency, use gunicorn/uvicorn.
    app.run(port=8080, debu

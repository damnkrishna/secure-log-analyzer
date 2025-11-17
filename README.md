# 🔐 Secure Log Analyzer

**Encrypted Logging + Attack Simulation + Offline Detection + Dashboard**

A complete InfoSec project that simulates real-world attacks, encrypts web server logs using AES-256-GCM, analyzes them for malicious activity, and visualizes the results through a dashboard.


---

# 📌 Features

### ✔ AES-256 Encrypted Logging

* Logs every HTTP request
* Encrypts each entry individually
* Uses Scrypt key derivation + stored salt

### ✔ Realistic Traffic Attack Simulation

Simulates real-world attacks including:

* SQL Injection
* XSS
* Local File Inclusion
* Remote File Inclusion
* Directory Traversal
* Admin/API scanning
* Bruteforce attempts
* Malicious User-Agents
* Bot/Scanner traffic
* Random IP spoofing

### ✔ Offline SIEM-Style Log Analyzer

* Decrypts all logs
* Detects multiple attack classes using patterns
* Generates summary reports
* Stores structured alerts

### ✔ Dashboard (Flask UI)

Shows:

* Attack distribution (pie chart)
* Summary of attack categories
* Latest alerts
* Clean, simple UI

---

# 📁 Project Structure

Based on your exact system layout:

```
secure-log-analyzer/
│
├── venv/                             # Virtual environment
│
└── scripts/
    │
    ├── server.py                     # Encrypted mini web-server
    ├── traffic.py                    # Attack generator
    ├── analyze.py                    # Offline analyzer (decrypt + detect)
    │
    ├── logs/
    │   ├── encrypted_logs.jl         # AES-encrypted logs
    │   └── key_salt.bin              # Salt for key derivation
    │
    ├── out/
    │   ├── summary_alerts.jsonl      # Detected attack events
    │   └── summary_report.txt        # Final summary report
    │
    └── dashboard/
        ├── app.py                    # Dashboard backend (Flask)
        │
        ├── static/
        │   └── style.css             # Dashboard styles
        │
        └── templates/
            └── index.html            # Dashboard UI (Chart.js)
```

---

# 🛠 Installation

### 1. Clone the project

```
git clone <your-repo-link>
cd secure-log-analyzer
```

### 2. Create a virtual environment

```
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```
pip install flask cryptography
```

---

# 🚀 How to Run the Project

## **Step 1: Start the encrypted web server**

```
cd scripts
python3 server.py
```

* It will ask for a **passphrase**
* Same passphrase is needed later for decryption

Server runs at:

```
http://127.0.0.1:8080
```

---

## **Step 2: Start the attack generator**

In a second terminal:

```
cd scripts
python3 traffic.py
```

This will simulate:

* SQLi
* XSS
* LFI & RFI
* Directory traversal
* Bruteforce
* Admin probing
* Random legitimate traffic
* Multi-IP spoofing

---

## **Step 3: Run the offline analyzer**

After generating traffic:

```
cd scripts
python3 analyze.py
```

Enter the **same passphrase** used in `server.py`.

Outputs generated in `scripts/out/`:

* `summary_report.txt`
* `summary_alerts.jsonl`

Analyzer prints:

* attack type
* IP
* request
* timestamp

And end-of-run summary:

* total attacks per category
* most active attacker IPs

---

## **Step 4: Launch the dashboard**

```
cd scripts/dashboard
python3 app.py
```

Open:

```
http://127.0.0.1:5000
```

Dashboard shows:

* Attack distribution chart
* Summary counts
* List of recent malicious events

---

# 🧠 How It Works (Simplified)

### **1️⃣ server.py**

* Receives traffic
* Formats log entries
* Encrypts them using AES-256-GCM
* Writes encrypted JSON lines to `logs/encrypted_logs.jl`

### **2️⃣ traffic.py**

* Sends realistic normal + malicious requests
* Random IPs + User-Agents
* Multiple attack categories

### **3️⃣ analyze.py**

* Derives AES key using Scrypt + salt
* Decrypts each log entry
* Applies regex attack signatures
* Logs alerts + summary

### **4️⃣ dashboard/**

* Reads summary + alert files
* Serves interactive charts with Flask

---

# 📄 Example Analyzer Output

```
[SQL Injection]  192.168.2.14 → /login.php?id=' OR 1=1 --
[XSS]            82.44.19.7   → /search?q=<script>alert(1)</script>
[LFI]            43.22.10.5   → /../../etc/passwd
[Bruteforce]     10.0.0.9     → multiple login failures
```

Summary:
```
SQLi: 104
XSS: 233
LFI: 12
RFI: 4
Traversal: 19
Brute Force: 37
Admin Scan: 88
Bot/Scanner: 27

Top IPs:
 - 45.166.23.8 : 121 requests
 - 76.22.10.7 : 64 requests
```


---

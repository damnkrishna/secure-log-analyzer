from flask import Flask, render_template
import json, os
from collections import Counter

ALERTS_FILE = "../out/summary_alerts.jsonl"
SUMMARY_FILE = "../out/summary_report.txt"

app = Flask(__name__)

def load_summary():
    summary = {}
    if os.path.exists(SUMMARY_FILE):
        with open(SUMMARY_FILE, "r") as f:
            for line in f:
                if ":" in line:
                    key, value = line.split(":", 1)
                    summary[key.strip()] = value.strip()
    return summary

def load_alerts():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except:
                    pass
    return alerts

@app.route("/")
def dashboard():
    summary = load_summary()
    alerts = load_alerts()

    attack_counts = Counter([a["attack"] for a in alerts]) if alerts else {}

    return render_template(
        "index.html",
        summary=summary,
        alerts=alerts,
        attack_labels=list(attack_counts.keys()),
        attack_values=list(attack_counts.values()),
    )

if __name__ == "__main__":
    app.run(port=5000, debug=True)
                                        

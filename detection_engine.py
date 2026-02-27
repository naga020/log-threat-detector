from detection_rules import RULES
from collections import Counter


def detect_threats(logs):

    alerts = []
    ip_counter = Counter()

    for log in logs:
        ip = log.get("ip")
        message = log.get("message", "")

        ip_counter[ip] += 1

        # -------- SQL Injection Rule --------
        for keyword in RULES["SQL Injection"]["keywords"]:
            if keyword.lower() in message.lower():
                alerts.append({
                    "ip": ip,
                    "attack_type": "SQL Injection",
                    "severity": RULES["SQL Injection"]["severity"],
                    "mitre": RULES["SQL Injection"]["mitre"],
                    "event_count": 1
                })

        # -------- Brute Force Rule --------
        if ip_counter[ip] >= RULES["Brute Force"]["threshold"]:
            alerts.append({
                "ip": ip,
                "attack_type": "Brute Force",
                "severity": RULES["Brute Force"]["severity"],
                "mitre": RULES["Brute Force"]["mitre"],
                "event_count": ip_counter[ip]
            })

    return alerts
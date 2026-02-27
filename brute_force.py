
from collections import defaultdict

def detect_brute_force(logs, threshold=5):
    failed_attempts = defaultdict(int)
    alerts = []

    for log in logs:
        if log["event"] == "LOGIN_FAILED":
            ip = log["ip"]
            failed_attempts[ip] += 1

            if failed_attempts[ip] == threshold:
                alerts.append({
                    "ip": ip,
                    "type": "Brute Force Attack",
                    "severity": "HIGH"
                })

    return alerts

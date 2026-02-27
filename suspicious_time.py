def detect_suspicious_time(logs, start_hour=0, end_hour=5):
    """
    Detect logins during unusual hours (default 12:00 AM - 5:00 AM)
    """
    alerts = []

    for log in logs:
        if log["event"] == "LOGIN_SUCCESS":
            time_parts = log["time"].split(":")
            hour = int(time_parts[0])

            if start_hour <= hour <= end_hour:
                alerts.append({
                    "ip": log["ip"],
                    "type": "Suspicious Login Time",
                    "severity": "MEDIUM"
                })

    return alerts

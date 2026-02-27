import json
import os
from datetime import datetime


def write_json_report(brute_force_results, port_scan_results):

    report_data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alerts": []
    }

    # -----------------------
    # Brute Force Alerts
    # -----------------------
    for alert in brute_force_results:
        report_data["alerts"].append({
            "ip": alert.get("ip", "Unknown"),
            "attack_type": alert.get("type", "Brute Force"),
            "event_count": alert.get("count", 1),
            "severity": alert.get("severity", "MEDIUM")
        })

    # -----------------------
    # Port Scan Alerts
    # -----------------------
    for alert in port_scan_results:
        report_data["alerts"].append({
            "ip": alert.get("ip", "Unknown"),
            "attack_type": alert.get("type", "Port Scan"),
            "event_count": alert.get("count", 1),
            "severity": alert.get("severity", "MEDIUM")
        })

    # -----------------------
    # Save File
    # -----------------------
    os.makedirs("reports", exist_ok=True)

    with open("reports/threat_report.json", "w") as file:
        json.dump(report_data, file, indent=4)

    print("📄 JSON Report Saved → reports/threat_report.json")

from parser.log_parser import read_logs
from detection.brute_force import detect_brute_force
from detection.port_scan import detect_port_scan
from utils.severity import format_alert, calculate_severity
from utils.report_writer import write_json_report
from database.db_manager import init_db, insert_alert


def main():

    # -------------------------------
    # Initialize Database
    # -------------------------------
    init_db()

    log_file = "logs/sample.log"

    print("\n📂 Reading Logs...")
    logs = read_logs(log_file)
    print(f"✅ Loaded {len(logs)} log entries\n")

    # -------------------------------
    # Run Detections
    # -------------------------------
    print("🔍 Running Brute Force Detection...\n")
    brute_force_results = detect_brute_force(logs)

    print("🔍 Running Port Scan Detection...\n")
    port_scan_results = detect_port_scan(logs)

    print("=== 🚨 Threat Alerts ===\n")

    all_alerts = []

    # -------------------------------
    # Brute Force Alerts
    # -------------------------------
    for alert in brute_force_results:
        from utils.severity import calculate_severity

        event_count = alert.get("count", 1)
        severity = calculate_severity(event_count)

        print(format_alert(
            ip=alert["ip"],
            attack_type=alert["type"],
            event_count=event_count
        ))

        # Save to DB
        insert_alert(
            alert["ip"],
            alert["type"],
            event_count,
            severity
        )

        all_alerts.append(alert)

    # -------------------------------
    # Port Scan Alerts
    # -------------------------------
    for alert in port_scan_results:
        event_count = alert.get("count", 1)
        severity = calculate_severity(event_count)

        print(format_alert(
            ip=alert["ip"],
            attack_type=alert["type"],
            event_count=event_count
        ))

        # Save to DB
    insert_alert(
            alert["ip"],
            alert["type"],
            event_count,
            severity
        )

    all_alerts.append(alert)

    if not all_alerts:
        print("✅ No threats detected.")

    # -------------------------------
    # Write JSON Report
    # -------------------------------
    write_json_report(brute_force_results, port_scan_results)

    print("\n📄 JSON Report Generated!")


if __name__ == "__main__":
    main()

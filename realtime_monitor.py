import time
from parser.log_parser import read_logs
from detection.brute_force import detect_brute_force
from detection.port_scan import detect_port_scan
from utils.severity import format_alert


def monitor_logs(log_file, interval=5):

    print("\n🟢 Real-Time Monitoring Started...")
    print("Watching log file for new threats...\n")

    last_size = 0

    while True:

        try:
            with open(log_file, "r") as file:
                file.seek(0, 2)
                current_size = file.tell()

            # If file changed
            if current_size != last_size:

                logs = read_logs(log_file)

                brute_results = detect_brute_force(logs)
                port_results = detect_port_scan(logs)

                if brute_results or port_results:
                    print("\n🚨 LIVE ALERT DETECTED 🚨\n")

                for alert in brute_results:
                    print(format_alert(
                        ip=alert.get("ip"),
                        attack_type=alert.get("type"),
                        event_count=alert.get("count", 1)
                    ))

                for alert in port_results:
                    print(format_alert(
                        ip=alert.get("ip"),
                        attack_type=alert.get("type"),
                        event_count=alert.get("count", 1)
                    ))

                last_size = current_size

            time.sleep(interval)

        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped.")
            break

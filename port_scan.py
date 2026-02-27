from collections import defaultdict


def detect_port_scan(logs, threshold=5):

    port_access = defaultdict(set)
    alerts = []

    for log in logs:

        if log.get("event") == "CONNECTION_ATTEMPT":

            ip = log.get("ip")
            port = log.get("port")

            # Safety check
            if ip and port:

                port_access[ip].add(port)

                if len(port_access[ip]) == threshold:

                    alerts.append({
                        "ip": ip,
                        "type": "Port Scan Detected",
                        "severity": "HIGH",
                        "count": len(port_access[ip])
                    })

    return alerts

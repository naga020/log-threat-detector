from detection_engine import detect_threats

sample_logs = [
    {"ip": "192.168.1.10", "message": "SELECT * FROM users"},
    {"ip": "192.168.1.10", "message": "Failed login"},
    {"ip": "192.168.1.10", "message": "Failed login"},
    {"ip": "192.168.1.10", "message": "Failed login"},
    {"ip": "192.168.1.10", "message": "Failed login"},
    {"ip": "192.168.1.10", "message": "Failed login"},
]

alerts = detect_threats(sample_logs)

print(alerts)
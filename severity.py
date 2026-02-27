def calculate_severity(event_count):
    if event_count <= 3:
        return "LOW"
    elif event_count <= 7:
        return "MEDIUM"
    else:
        return "HIGH"


def format_alert(ip, attack_type, event_count):
    severity = calculate_severity(event_count)

    message = (
        f"🚨 ALERT | {attack_type}\n"
        f"IP Address : {ip}\n"
        f"Events     : {event_count}\n"
        f"Severity   : {severity}\n"
        f"-----------------------------------"
    )

    return message

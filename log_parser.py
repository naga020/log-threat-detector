def read_logs(file_path):

    logs = []

    with open(file_path, "r") as file:

        for line in file:

            parts = line.strip().split(" ")

            # Minimum required: date time event ip
            if len(parts) < 4:
                continue

            log_entry = {
                "date": parts[0],
                "time": parts[1],
                "event": parts[2],
                "ip": parts[3]
            }

            # If port exists → add it
            if len(parts) >= 5:
                log_entry["port"] = parts[4]

            logs.append(log_entry)

    return logs

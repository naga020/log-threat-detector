RULES = {
    "SQL Injection": {
        "keywords": ["SELECT", "DROP", "--", "UNION"],
        "severity": "HIGH",
        "mitre": "T1190"
    },
    "Brute Force": {
        "threshold": 5,
        "severity": "MEDIUM",
        "mitre": "T1110"
    }
}
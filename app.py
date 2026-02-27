from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from collections import Counter
import os
import re

from detection_engine import detect_threats
from .auth_db import init_user_db, add_user, verify_user, User
from database.db_manager import (
    get_all_alerts,
    insert_alert,
    init_db,
    clear_alerts
)

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Initialize databases
init_db()
init_user_db()

# Create default admin
add_user("admin", "admin123", "admin")

# -----------------------------
# LOGIN SETUP
# -----------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User(user_id, "admin")


# -----------------------------
# LOGIN
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user_data = verify_user(username, password)

        if user_data:
            login_user(User(user_data["username"], user_data["role"]))
            return redirect(url_for("home"))

        return "Invalid Credentials"

    return render_template("login.html")


# -----------------------------
# LOGOUT
# -----------------------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# -----------------------------
# DASHBOARD
# -----------------------------
@app.route("/")
@login_required
def home():

    alerts = get_all_alerts()

    attack_types = [a["attack_type"] for a in alerts]
    severities = [a["severity"] for a in alerts]
    ips = [a["ip"] for a in alerts]

    attack_count = Counter(attack_types)
    severity_count = Counter(severities)
    top_ips = Counter(ips).most_common(5)
    success = request.args.get("success")

    return render_template(
        "index.html",
        alerts=alerts,
        attack_count=dict(attack_count),
        severity_count=dict(severity_count),
        top_ips=top_ips,
        success = success
    )


# -----------------------------
# AUTO REFRESH API
# -----------------------------
@app.route("/api/alerts")
@login_required
def api_alerts():

    alerts = get_all_alerts()

    attack_types = [a["attack_type"] for a in alerts]
    severities = [a["severity"] for a in alerts]
    ips = [a["ip"] for a in alerts]

    return jsonify({
        "alerts": alerts,
        "attack_count": dict(Counter(attack_types)),
        "severity_count": dict(Counter(severities)),
        "top_ips": Counter(ips).most_common(5)
    })


# -----------------------------
# IP Extraction Helper
# -----------------------------
def extract_ip(log_line):
    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_line)
    if match:
        return match.group(0)
    return "Unknown"


# -----------------------------
# UPLOAD LOG FILE
# -----------------------------
@app.route("/upload_logs", methods=["POST"])
@login_required
def upload_logs():

    if "logfile" not in request.files:
        return "No file uploaded"

    file = request.files["logfile"]

    if file.filename == "":
        return "No selected file"

    # Save file temporarily
    os.makedirs("uploads", exist_ok=True)
    filepath = os.path.join("uploads", file.filename)
    file.save(filepath)

    # Parse file
    parsed_logs = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed_logs.append({
                "ip": extract_ip(line),
                "message": line.strip()
            })

    # Clear old alerts
    clear_alerts()

    # Detect threats
    alerts = detect_threats(parsed_logs)

    # Insert alerts into DB
    for alert in alerts:
        insert_alert(
            alert["ip"],
            alert["attack_type"],
            alert["event_count"],
            alert["severity"],
            alert["mitre"]
        )

    # Optional: delete uploaded file after processing
    os.remove(filepath)

    return redirect("/?success=1")


if __name__ == "__main__":
    app.run(debug=True)
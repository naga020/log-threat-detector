# Threat Detection Dashboard (SOC-Oriented Project)

## Overview
A web-based threat detection system that analyzes uploaded log files,
detects potential attacks, and maps them to MITRE ATT&CK techniques.

## Features
- User authentication
- Log file upload & parsing
- SQL Injection & Brute Force detection
- MITRE ATT&CK mapping
- Severity classification
- Dashboard visualization
- SQLite database storage

## Technologies Used
- Python
- Flask
- SQLite
- Chart.js

## MITRE Mapping
- T1110 - Brute Force
- T1190 - Exploit Public-Facing Application

## How to Run
python -m dashboard.app

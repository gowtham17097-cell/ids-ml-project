"""
Logs detected intrusions to console and to a CSV file for the dashboard.
"""

import csv
import os
from datetime import datetime

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_LOG_PATH = os.path.join(_PROJECT_ROOT, "logs", "alerts.csv")

_HEADERS = ["timestamp", "src_ip", "dst_ip", "service", "protocol", "prediction", "confidence"]


def _ensure_log_file():
    os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
    if not os.path.exists(_LOG_PATH):
        with open(_LOG_PATH, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_HEADERS)
            writer.writeheader()


def log_result(result: dict):
    """
    Logs EVERY prediction (normal or attack) to CSV for dashboard stats,
    but only prints a console warning for attacks.
    """
    _ensure_log_file()

    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "src_ip": result["src_ip"],
        "dst_ip": result["dst_ip"],
        "service": result["service"],
        "protocol": result["protocol"],
        "prediction": result["prediction"],
        "confidence": result["confidence"],
    }

    with open(_LOG_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_HEADERS)
        writer.writerow(row)

    if result["prediction"] == "attack":
        print(f"🚨 ALERT: {result['protocol'].upper()} attack detected from "
              f"{result['src_ip']} -> {result['dst_ip']} ({result['service']}) "
              f"— confidence {result['confidence']:.0%}")
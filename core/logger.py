import os
from datetime import datetime

os.makedirs("logs", exist_ok=True)


def log_alert(message):
    with open("logs/alerts.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] {message}\n")
from scapy.all import Raw, IP
from core.state import stats
from core.logger import log_alert
import re

KEYWORDS = [
    "password",
    "passwd",
    "login",
    "username",
    "authorization"
]

REGEX = re.compile(
    r"(password|passwd|pwd|login|username)=([^&\\s]+)",
    re.IGNORECASE
)


def detect(packet):
    if not packet.haslayer(Raw):
        return

    try:
        payload = packet[Raw].load.decode(errors="ignore")
    except:
        return

    payload_lower = payload.lower()

    for keyword in KEYWORDS:
        if keyword in payload_lower:

            matches = REGEX.findall(payload)

            stats["suspicious"] += 1
            stats["credentials"] += 1

            src = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst = packet[IP].dst if packet.haslayer(IP) else "unknown"

            alert = f"Plaintext credential detected | {src} -> {dst}"

            if matches:
                for key, value in matches:
                    alert += f" | {key}={value}"

            stats["alerts"].append(alert)
            log_alert(alert)

            break
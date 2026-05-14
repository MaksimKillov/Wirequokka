from scapy.all import TCP, IP
from core.state import port_scan_tracker, stats
from core.logger import log_alert
import time

THRESHOLD = 20
WINDOW = 10


def detect(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    src = packet[IP].src
    port = packet[TCP].dport

    current = time.time()

    if src not in port_scan_tracker:
        port_scan_tracker[src] = []

    port_scan_tracker[src].append((port, current))

    recent = [
        p for p in port_scan_tracker[src]
        if current - p[1] < WINDOW
    ]

    port_scan_tracker[src] = recent

    unique_ports = len(set(p[0] for p in recent))

    if unique_ports > THRESHOLD:
        alert = f"Possible port scan from {src}"

        stats["suspicious"] += 1
        stats["alerts"].append(alert)

        log_alert(alert)
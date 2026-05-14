from scapy.all import DNSQR
from core.state import stats


def detect(packet):
    if packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode(errors="ignore")

        stats["dns_requests"] += 1

        alert = f"DNS Query -> {domain}"
        stats["alerts"].append(alert)
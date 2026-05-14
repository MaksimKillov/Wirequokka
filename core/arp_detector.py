from scapy.all import ARP
from core.state import arp_table, stats
from core.logger import log_alert


def detect(packet):
    if not packet.haslayer(ARP):
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc

    if ip in arp_table and arp_table[ip] != mac:
        alert = (
            f"ARP spoof detected | IP: {ip} | "
            f"Old MAC: {arp_table[ip]} | New MAC: {mac}"
        )

        stats["suspicious"] += 1
        stats["arp_alerts"] += 1
        stats["alerts"].append(alert)

        log_alert(alert)

    arp_table[ip] = mac
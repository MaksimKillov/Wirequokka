from scapy.all import sniff, IP

from core.state import stats
from core.arp_detector import detect as arp_detect
from core.credential_detector import detect as cred_detect
from core.dns_monitor import detect as dns_detect
from core.portscan_detector import detect as portscan_detect


def process_packet(packet):

    stats["packets"] += 1

    if packet.haslayer(IP):
        stats["devices"].add(packet[IP].src)

    arp_detect(packet)
    cred_detect(packet)
    dns_detect(packet)
    portscan_detect(packet)


def start_sniffer():
    sniff(prn=process_packet, store=False)
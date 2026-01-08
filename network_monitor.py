iface_name = "Wi-Fi"

from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.layers.l2 import ARP
from datetime import datetime
import os
import time
import portalocker
import json
import queue
import psutil

# -------------------------------
# Interface selection
# -------------------------------
def choose_interface():
    interfaces = list(psutil.net_if_addrs().keys())
    print("Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  {i}: {iface}")

choose_interface()

# -------------------------------
# Files
# -------------------------------
LOG_FILE = "imp_detailed_log.json"
open(LOG_FILE, "a").close()

# -------------------------------
# Queue (single producer)
# -------------------------------
packet_queue = queue.Queue(maxsize=50000)

# -------------------------------
# Protocol map
# -------------------------------
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}

# -------------------------------
# Packet logger (ONLY writes)
# -------------------------------
def write_log(data):
    try:
        with open(LOG_FILE, "a") as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.write(json.dumps(data) + "\n")
            portalocker.unlock(f)
    except Exception as e:
        print("Log write error:", e)

# -------------------------------
# Packet parser (enqueue ONCE)
# -------------------------------
def log_packet(packet):
    try:
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S.%f")

        data = {
            "Time": timestamp,
            "Interface": packet.sniffed_on,
            "Packet_Length": len(packet),

            "Protocol": "Unknown",
            "Src_IP": None,
            "Dst_IP": None,
            "Src_Port": None,
            "Dst_Port": None,

            "Flags": None,
            "TTL": None,
            "Payload_Size": 0,

            "MAC_Src": None,
            "MAC_Dst": None,
            "Ether_Type": None
        }

        # Ethernet
        if Ether in packet:
            data["MAC_Src"] = packet[Ether].src
            data["MAC_Dst"] = packet[Ether].dst
            data["Ether_Type"] = hex(packet[Ether].type)

        # ARP
        if ARP in packet:
            data["Protocol"] = "ARP"
            data["Src_IP"] = packet[ARP].psrc
            data["Dst_IP"] = packet[ARP].pdst

        # IPv4
        elif IP in packet:
            proto = packet[IP].proto
            data["Protocol"] = PROTO_MAP.get(proto, f"IP({proto})")
            data["Src_IP"] = packet[IP].src
            data["Dst_IP"] = packet[IP].dst
            data["TTL"] = packet[IP].ttl

        # IPv6
        elif IPv6 in packet:
            data["Protocol"] = "IPv6"
            data["Src_IP"] = packet[IPv6].src
            data["Dst_IP"] = packet[IPv6].dst
            data["TTL"] = packet[IPv6].hlim

        # TCP
        if TCP in packet:
            data["Protocol"] = "TCP"
            data["Src_Port"] = packet[TCP].sport
            data["Dst_Port"] = packet[TCP].dport
            data["Flags"] = str(packet[TCP].flags)

        # UDP
        elif UDP in packet:
            data["Protocol"] = "UDP"
            data["Src_Port"] = packet[UDP].sport
            data["Dst_Port"] = packet[UDP].dport

        # Payload size only (NO PRINTING)
        if Raw in packet:
            data["Payload_Size"] = len(packet[Raw].load)

        # Enqueue ONCE
        packet_queue.put_nowait(data)

    except queue.Full:
        pass
    except Exception as e:
        print("Packet parse error:", e)

# -------------------------------
# Background writer (consumer)
# -------------------------------
def process_queue():
    while True:
        try:
            pkt = packet_queue.get()
            write_log(pkt)
        except Exception:
            pass

# -------------------------------
# Start writer thread
# -------------------------------
import threading
threading.Thread(target=process_queue, daemon=True).start()

# -------------------------------
# Start sniffing
# -------------------------------
print("\n[+] SecureGate packet capture started...\n")
sniff(iface=iface_name, prn=log_packet, store=False)

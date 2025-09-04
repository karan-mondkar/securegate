from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw
from datetime import datetime
import os
import time
import portalocker
import json
import queue

last_run = 0

# Ensure files exist
open("securegate_detailed_log1.json", "a").close()
open("securegate_detailed_log2.json", "a").close()
open("imp_detailed_log.json", "a").close()

def safe(data, key, default="N/A"):
    return str(data.get(key, default)).strip()

request_queue = queue.Queue(maxsize=50000)

def logfile(data):
    global last_run
    current_time = time.time()
    source_file = "securegate_detailed_log1.json"
    destination_file = "securegate_detailed_log2.json"

    request = {
        "Time": safe(data, "Time"),
        "Src_IP": safe(data, "Src_IP"),
        "Dst_IP": safe(data, "Dst_IP"),
        "Protocol": safe(data, "Protocol", "Unknown"),
        "Dst_Port": safe(data, "Dst_Port")
    }
    request_queue.put(request)

    # Process queue → write logs
    while not request_queue.empty():
        a = request_queue.get()
        try:
            with open(source_file, "a") as f1:
                portalocker.lock(f1, portalocker.LOCK_EX)
                f1.write(json.dumps(a) + "\n")
                portalocker.unlock(f1)

            with open("imp_detailed_log.json", "a") as f2:
                f2.write(json.dumps(a) + "\n")

        except portalocker.exceptions.LockException:
            print("File is locked, re-adding to queue")
            request_queue.put(a)

    # Copy every 3 seconds
    if current_time - last_run >= 3:
        last_run = current_time
        try:
            if os.path.exists(source_file):
                with open(source_file, "r") as src:
                    try:
                        portalocker.lock(src, portalocker.LOCK_EX | portalocker.LOCK_NB)
                        content = src.read()

                        with open(destination_file, "a") as dest:
                            dest.write(content)

                        portalocker.unlock(src)
                    except portalocker.exceptions.LockException:
                        print("Source file is locked. Try again next time.")
                os.remove(source_file)
        except Exception as e:
            print(f"Error during file copy or delete: {e}")


PROTO_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

def log_packet(packet):
    global request_queue, data
    try:
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S.%f")
        data = {
            "Time": timestamp,
            "Protocol": "Unknown",
            "Src_IP": "N/A",
            "Src_Port": "N/A",
            "Dst_IP": "N/A",
            "Dst_Port": "N/A",
            "Flags": "N/A",
            "TTL": "N/A",
            "Window": "N/A",
            "Payload_Size": 0,
            "MAC_Src": "N/A",
            "MAC_Dst": "N/A"
        }

        # MAC
        if Ether in packet:
            data["MAC_Src"] = packet[Ether].src
            data["MAC_Dst"] = packet[Ether].dst

        # IPv4
        if IP in packet:
            proto_num = packet[IP].proto
            data["Protocol"] = PROTO_MAP.get(proto_num, f"Unknown({proto_num})")
            data["Src_IP"] = packet[IP].src
            data["Dst_IP"] = packet[IP].dst
            data["TTL"] = packet[IP].ttl

        # IPv6
        elif IPv6 in packet:
            proto_num = packet[IPv6].nh
            data["Protocol"] = PROTO_MAP.get(proto_num, f"Unknown({proto_num})")
            data["Src_IP"] = packet[IPv6].src
            data["Dst_IP"] = packet[IPv6].dst
            data["TTL"] = packet[IPv6].hlim

        # TCP
        if TCP in packet:
            data["Protocol"] = "TCP"
            data["Src_Port"] = packet[TCP].sport
            data["Dst_Port"] = packet[TCP].dport
            data["Flags"] = str(packet[TCP].flags)
            data["Window"] = packet[TCP].window
            if Raw in packet:
                data["Payload_Size"] = len(packet[Raw].load)

        # UDP
        elif UDP in packet:
            data["Protocol"] = "UDP"
            data["Src_Port"] = packet[UDP].sport
            data["Dst_Port"] = packet[UDP].dport
            if Raw in packet:
                data["Payload_Size"] = len(packet[Raw].load)

        # ICMP
        elif ICMP in packet:
            data["Protocol"] = "ICMP"
            if Raw in packet:
                data["Payload_Size"] = len(packet[Raw].load)

        # Push
        request_queue.put(data)

    except Exception as e:
        print(f"Error parsing packet: {e}")

    print(data)
    logfile(data)


while True:
    sniff(iface="Wi-Fi", prn=log_packet, store=False, count=0)

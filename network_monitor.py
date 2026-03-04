from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.layers.l2 import ARP
from datetime import datetime
import os
import time
import portalocker
import json
import queue
import psutil
from dotenv import load_dotenv
import os
import sys
import traceback

#current directory of the script 
def get_runtime_dir():
    if getattr(sys, "frozen", False):   #help to work as executable as well..
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

RUNTIME_DIR = get_runtime_dir()

ENV_FILE = os.path.join(RUNTIME_DIR, "securegate.env")

if not os.path.exists(ENV_FILE):
    raise RuntimeError(f"securegate.env not found at: {ENV_FILE}")

load_dotenv(ENV_FILE)

#  SECUREGATE BASE DIR 
BASE_DIR = os.getenv("SECUREGATE_BASE_DIR")
if not BASE_DIR:
    raise RuntimeError("SECUREGATE_BASE_DIR is not set in securegate.env")

BASE_DIR = os.path.abspath(BASE_DIR)
os.makedirs(BASE_DIR, exist_ok=True)


# GLOBAL CONFIG (SAFE)


LOG_FILE = os.path.join(BASE_DIR, "securegate_error.log")

def log_error(message, exc=None):
    """
    Appends error message to securegate_error.log.
    File is created automatically if it does not exist.
    """
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write(f"TIME : {time.ctime()}\n")
            f.write(f"ERROR: {message}\n")

            if exc:
                f.write("TRACEBACK:\n")
                f.write("".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                ))

            f.write("\n")

    except Exception:
        pass


INTERFACE_NAME = os.getenv("SECUREGATE_INTERFACE", "eth0")

SECUREGATE_PACKET_QUEUE_SIZE = int(
    os.getenv("SECUREGATE_PACKET_QUEUE_SIZE", "50000")
)

SECUREGATE_LOG_FILE_STAGE1 = os.getenv(
    "SECUREGATE_LOG_FILE_STAGE1", "securegate_detailed_log1.json"
)

SECUREGATE_LOG_FILE_STAGE2 = os.getenv(
    "SECUREGATE_LOG_FILE_STAGE2", "securegate_detailed_log2.json"
)

SECUREGATE_LOG_FILE_IMPORTANT = os.getenv(
    "SECUREGATE_LOG_FILE_IMPORTANT", "imp_detailed_log.json"
)

SECUREGATE_LOG_COPY_INTERVAL = int(
    os.getenv("SECUREGATE_LOG_COPY_INTERVAL", "3")
)

# 
# INTERFACE
# 
iface_name = INTERFACE_NAME

def choose_interface():
    """
    Lists all network interfaces and prompts the user to choose one.
    (Kept as-is, only informational)
    """
    interfaces = list(psutil.net_if_addrs().keys())
    print("Available Network Interfaces:")
    for i, iface_name in enumerate(interfaces):
        print(f"  {i}: {iface_name}")


#choose_interface()

last_run = 0

# ENSURE LOG FILES EXIST (GLOBAL VALUES)

import os

#  Define paths and ensure files exist
# 
LOG_FILES = [
    SECUREGATE_LOG_FILE_STAGE1,
    SECUREGATE_LOG_FILE_STAGE2,
    SECUREGATE_LOG_FILE_IMPORTANT
]

for log_file in LOG_FILES:
    log_path = os.path.join(BASE_DIR, log_file)
    if not os.path.exists(log_path):
        with open(log_path, "a") as f:
            f.close()
        print(f" Created log file: {log_file}")


def safe(data, key, default="N/A"):
    return str(data.get(key, default)).strip()


# 
# QUEUE SIZE (GLOBAL VALUE)
# 

request_queue = queue.Queue(maxsize=SECUREGATE_PACKET_QUEUE_SIZE)

def logfile(data):
        
    global last_run
    current_time = time.time()

    source_file = os.path.join(BASE_DIR, SECUREGATE_LOG_FILE_STAGE1)
    destination_file = os.path.join(BASE_DIR, SECUREGATE_LOG_FILE_STAGE2)
    important_file = os.path.join(BASE_DIR, SECUREGATE_LOG_FILE_IMPORTANT)

    request = {
        "Time": safe(data, "Time"),
        "Src_IP": safe(data, "Src_IP"),
        "Dst_IP": safe(data, "Dst_IP"),
        "Protocol": safe(data, "Protocol", "Unknown"),
        "Dst_Port": safe(data, "Dst_Port")
    }

    request_queue.put(request)

    #                PROCESS QUEUE 
    while not request_queue.empty():
        a = request_queue.get()
        try:
            # Stage 1 log
            with open(source_file, "a") as f1:
                portalocker.lock(f1, portalocker.LOCK_EX)
                f1.write(json.dumps(a) + "\n")
                portalocker.unlock(f1)

            # Important log 
            with open(important_file, "a") as f2:
                f2.write(json.dumps(a) + "\n")

        except portalocker.exceptions.LockException as e:
            log_error("File lock error", e)
            request_queue.put(a)

    #                    COPY INTERVAL  
    if current_time - last_run >= SECUREGATE_LOG_COPY_INTERVAL:
        last_run = current_time

        try:
            if os.path.exists(source_file):
                with open(source_file, "r") as src:
                    portalocker.lock(src, portalocker.LOCK_EX | portalocker.LOCK_NB)
                    content = src.read()
                    portalocker.unlock(src)

                with open(destination_file, "a") as dest:
                    dest.write(content)

                os.remove(source_file)

        except Exception as e:
            log_error("Log rotation failed", e)




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

    if Raw in packet:
        print(packet[Raw].load)

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
            "MAC_Dst": "N/A",

            "Interface": packet.sniffed_on,
            "Packet_Length": len(packet),
            "Ether_Type": "N/A",
            "IP_Flags": "N/A",
            "Fragment_Offset": "N/A",
            "Seq": "N/A",
            "Ack": "N/A",
            "TCP_Options": "N/A",
            "ICMP_Type": "N/A",
            "ICMP_Code": "N/A",
            "IPv6_FlowLabel": "N/A",
            "IPv6_TrafficClass": "N/A"
        }

        if Ether in packet:
            data["MAC_Src"] = packet[Ether].src
            data["MAC_Dst"] = packet[Ether].dst
            data["Ether_Type"] = hex(packet[Ether].type)

        if ARP in packet:
            data["Protocol"] = "ARP"
            data["Src_IP"] = packet[ARP].psrc
            data["Dst_IP"] = packet[ARP].pdst

        if IP in packet:
            proto_num = packet[IP].proto
            data["Protocol"] = PROTO_MAP.get(proto_num, f"Unknown({proto_num})")
            data["Src_IP"] = packet[IP].src
            data["Dst_IP"] = packet[IP].dst
            data["TTL"] = packet[IP].ttl
            data["IP_Flags"] = str(packet[IP].flags)
            data["Fragment_Offset"] = packet[IP].frag

        elif IPv6 in packet:
            proto_num = packet[IPv6].nh
            data["Protocol"] = PROTO_MAP.get(proto_num, f"Unknown({proto_num})")
            data["Src_IP"] = packet[IPv6].src
            data["Dst_IP"] = packet[IPv6].dst
            data["TTL"] = packet[IPv6].hlim
            data["IPv6_FlowLabel"] = packet[IPv6].fl
            data["IPv6_TrafficClass"] = packet[IPv6].tc

        if TCP in packet:
            data["Protocol"] = "TCP"
            data["Src_Port"] = packet[TCP].sport
            data["Dst_Port"] = packet[TCP].dport
            data["Flags"] = str(packet[TCP].flags)
            data["Window"] = packet[TCP].window
            data["Seq"] = packet[TCP].seq
            data["Ack"] = packet[TCP].ack
            data["TCP_Options"] = str(packet[TCP].options)

            if Raw in packet:
                data["Payload_Size"] = len(packet[Raw].load)

        elif UDP in packet:
            data["Protocol"] = "UDP"
            data["Src_Port"] = packet[UDP].sport
            data["Dst_Port"] = packet[UDP].dport

            if Raw in packet:
                data["Payload_Size"] = len(packet[Raw].load)

        elif ICMP in packet:
            data["Protocol"] = "ICMP"
            data["ICMP_Type"] = packet[ICMP].type
            data["ICMP_Code"] = packet[ICMP].code

            if Raw in packet:
                data["Payload_Size"] = len(packet[Raw].load)

        request_queue.put(data)

    except Exception as e:
        log_error("Engine crashed during startup", e)
        print(f"Error parsing packet: {e}")

    print(data)
    logfile(data)
    
while True:
    
    SECUREGATE_NETWORK_MONITOR = os.getenv("SECUREGATE_NETWORK_MONITOR", "False")
    if not SECUREGATE_NETWORK_MONITOR:
        time.sleep(2)
    else:
        sniff(iface=iface_name, prn=log_packet, store=False, count=0)

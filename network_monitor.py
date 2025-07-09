


from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from datetime import datetime
import os
import time

import queue

last_run=0 

open("securegate_detailed_log1.txt", "a").close()
open("securegate_detailed_log2.txt", "a").close()

request_queue = queue.Queue(maxsize=5000)
def logfile(data):
    global last_run
    current_time = time.time()
    source_file = "securegate_detailed_log1.txt"
    destination_file = "securegate_detailed_log2.txt"

    formatted = (
        f"[{data['Time']}] {data['Protocol']} | "
        f"{data['Src_IP']}:{data['Src_Port']} -> {data['Dst_IP']}:{data['Dst_Port']} | "
        f"Flags: {data['Flags']} | TTL: {data['TTL']} | Window: {data['Window']} | "
        f"Payload: {data['Payload_Size']} bytes | MAC: {data['MAC_Src']} -> {data['MAC_Dst']}"
    )

    request= (
    f"[{data['Time']}] {data['Src_IP']} -> {data['Dst_IP']} | "
    f"Protocol: {data['Protocol']} | Dst Port: {data['Dst_Port']}"
    )

    request_queue.put(request)

    if not request_queue.empty():
        while request_queue.empty():    
            with open(source_file, "a") as f:
                f.write(request_queue.get() + "\n")

    if current_time - last_run >= 10:
        last_run = current_time        
        if os.path.exists(source_file):
            try:
                # Open the source file in read mode
                with open(source_file, "r") as src:
                    content = src.read()

                # Open the destination file in append mode and write content
                with open(destination_file, "a") as dest:
                    dest.write(content)
                os.remove(source_file)
            except :
                pass
            
            
            
            












def log_packet(packet):
        global request_queue,data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
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
        if Ether in packet:
            data["MAC_Src"] = packet[Ether].src
            data["MAC_Dst"] = packet[Ether].dst

        if IP in packet:
            data["Src_IP"] = packet[IP].src
            data["Dst_IP"] = packet[IP].dst
            data["TTL"] = packet[IP].ttl

        if TCP in packet:
            data["Protocol"] = "TCP"
            data["Src_Port"] = packet[TCP].sport
            data["Dst_Port"] = packet[TCP].dport
            data["Flags"] = packet[TCP].flags
            data["Window"] = packet[TCP].window
        elif UDP in packet:
            data["Protocol"] = "UDP"
            data["Src_Port"] = packet[UDP].sport
            data["Dst_Port"] = packet[UDP].dport
        elif ICMP in packet:
            data["Protocol"] = "ICMP"

        if Raw in packet:
            data["Payload_Size"] = len(packet[Raw].load)

        

       
        logfile(data)



sniff(iface="eth0", prn=log_packet, store=False)

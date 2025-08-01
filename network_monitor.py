


from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from datetime import datetime
import os
import time
import portalocker
import json
import queue

last_run=0 

open("securegate_detailed_log1.json", "a").close()
open("securegate_detailed_log2.json", "a").close()

open("imp_detailed_log.json", "a").close()

def safe(data, key, default="N/A"):
    return str(data.get(key, default)).strip()

request_queue = queue.Queue(maxsize=50000)
def logfile(data):
    open("securegate_detailed_log1.json", "a").close()
    global last_run
    current_time = time.time()
    source_file = "securegate_detailed_log1.json"
    destination_file = "securegate_detailed_log2.json"

    formatted = (
        f"[{data['Time']}] {data['Protocol']} | "
        f"{data['Src_IP']}:{data['Src_Port']} -> {data['Dst_IP']}:{data['Dst_Port']} | "
        f"Flags: {data['Flags']} | TTL: {data['TTL']} | Window: {data['Window']} | "
        f"Payload: {data['Payload_Size']} bytes | MAC: {data['MAC_Src']} -> {data['MAC_Dst']}"
    )

    request = {
    "time": safe(data, "Time"),
    "src_ip": safe(data, "Src_IP"),
    "dst_ip": safe(data, "Dst_IP"),
    "protocol": safe(data, "Protocol", "Unknown"),
    "dst_port": safe(data, "Dst_Port")
    }
    request_queue.put(request)

    if not request_queue.empty():
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
            
        


    if current_time - last_run >= 2:
        last_run = current_time        
        try:
            if os.path.exists(source_file):
                with open(source_file, "r") as src:
                    try:
                        # Try locking the source file (non-blocking)
                        portalocker.lock(src, portalocker.LOCK_EX | portalocker.LOCK_NB)
                        content = src.read()

                        with open(destination_file, "a") as dest:
                            dest.write(content)

                        portalocker.unlock(src)
                        src.close()
                        os.remove(source_file)

                    except portalocker.exceptions.LockException:
                        print("Source file is locked. Try again next time.")

        except Exception as e:
            print(f"Error during file copy or delete: {e}")











def log_packet(packet):
        global request_queue,data
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
        except Exception as e:
            print(e)
            

        #print(data)
        logfile(data)

sniff(iface="Wi-Fi", prn=log_packet, store=False)


#




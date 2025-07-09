import mysql.connector  # db connection
import subprocess       # block/unblock
import socket           # internet connection
import requests         # country lookup
import json
import time
from datetime import datetime, timedelta

request={}


def fileins(req):
    line_to_append = str(req) + "\n"
    file_path = "output.txt"
    with open(file_path, "a", encoding="utf-8") as file:
        file.write(line_to_append)

def monitor_requests():
    global request_queue, temp_queue
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == "ESTABLISHED" and conn.raddr and conn.laddr:
            src_ip = conn.laddr.ip
            src_port = conn.laddr.port
            dst_ip = conn.raddr.ip
            dst_port = conn.raddr.port
            protocol = conn.type  # socket.SOCK_STREAM (TCP) or socket.SOCK_DGRAM (UDP)
            protocol_str = "TCP" if protocol == socket.SOCK_STREAM else "UDP"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

            request_data = {
                "Src_IP": src_ip,
                "Src_Port": src_port,
                "Dst_IP": dst_ip,
                "Dst_Port": dst_port,
                "Protocol": protocol_str,
                "Time": timestamp
            }

            fileins(request_data)
            request_queue.put(request_data)
            temp_queue.append(request_data)

while True:
    monitor_requests()

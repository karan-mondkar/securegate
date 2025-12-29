import mysql.connector
from collections import defaultdict

PORT_THRESHOLD = 10
TIME_WINDOW = 30  # minutes
MIN_PACKETS = 50
SYN_RATIO_THRESHOLD = 0.8


def fetch_last_30_min_packets():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="Securegate",
        port=3306,
    )
    cursor = connection.cursor()

    query = """
    SELECT 
        request_time,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        tcp_flags,
        payload_size
    FROM iprequest_junction
    WHERE request_time >= NOW() - INTERVAL 30 MINUTE
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    detection_packets = []
    for row in rows:
        detection_packets.append({
            "time": row[0],
            "src_ip": row[1],
            "dst_ip": row[2],
            "src_port": row[3],
            "dst_port": row[4],
            "protocol": row[5],
            "tcp_flags": row[6],
            "payload_size": row[7],
        })

    print(f"[INFO] Loaded {len(detection_packets)} packets")

    #PORT SCAN LOGIC 



    ip_ports = defaultdict(set)

    for pkt in detection_packets:
        if pkt["dst_port"] is not None:
            ip_ports[pkt["src_ip"]].add(pkt["dst_port"])

    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_THRESHOLD:
            print(f"[PORT SCAN] {ip} → {len(ports)} ports")

    # MULTI-IP MASS SCAN 


    all_ports = set()
    for ports in ip_ports.values():
        all_ports.update(ports)

    if len(all_ports) >= 1000:
        suspicious_ips = []
        for ip, ports in ip_ports.items():
            if ports & all_ports:
                suspicious_ips.append(ip)

        print("[MASS SCAN IPs]", suspicious_ips)
        print("Total distinct ports:", len(all_ports))

    # SYN FLOOD LOGIC 

    
    tcp_stats = defaultdict(lambda: {
        "syn": 0,
        "ack": 0,
        "syn_ack": 0,
        "fin": 0
    })

    for pkt in detection_packets:
        if pkt["protocol"] != "TCP" or not pkt["tcp_flags"]:
            continue

        flag = pkt["tcp_flags"]
        ip = pkt["src_ip"]

        if flag == "S":
            tcp_stats[ip]["syn"] += 1
        elif flag == "SA":
            tcp_stats[ip]["syn_ack"] += 1
        elif flag in ("A", "PA"):
            tcp_stats[ip]["ack"] += 1
        elif flag in ("F", "FA"):
            tcp_stats[ip]["fin"] += 1

    for ip, stats in tcp_stats.items():
        total = sum(stats.values())
        if total < MIN_PACKETS:
            continue

        syn_ratio = stats["syn"] / total
        ack_ratio = stats["ack"] / total

        if syn_ratio >= SYN_RATIO_THRESHOLD and ack_ratio < 0.2:
            print(f"[SYN FLOOD] {ip} | SYN={stats['syn']} ACK={stats['ack']}")

    cursor.close()
    connection.close()


fetch_last_30_min_packets()

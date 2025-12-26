import mysql.connector
def fetch_last_30_min_packets():
    connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="Securegate",
                port=3306,
            )
    cursor=connection.cursor()
        

    """
    Fetch all packet data from last 30 minutes into memory.
    Returns a list of dictionaries.
    """

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
        pack = {
            "time": row[0],
            "src_ip": row[1],
            "dst_ip": row[2],
            "src_port": row[3],
            "dst_port": row[4],
            "protocol": row[5],
            "tcp_flags": row[6],
            "payload_size": row[7],
        }
        detection_packets.append(pack)

    print(f"[INFO] Loaded {len(detection_packets)} packets into memory")
    
    #detection of port scan
    for pkt in detection_packets:
        ip_ports=[]
        if pkt["dst_port"] is not None:
            ip_ports[pkt["src_ip"]].append(pkt["dst_port"])
            print(ip_ports)

fetch_last_30_min_packets()
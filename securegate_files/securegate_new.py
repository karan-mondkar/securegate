import mysql.connector #db connection
import subprocess #block unblock fun sathi
import socket # internet connection
import requests #country find
import ipaddress
import json
import time 
from datetime import datetime,timedelta



from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from datetime import datetime
import os

import subprocess
import platform



import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



from mailersend import MailerSendClient, EmailBuilder

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

counter_temp=0
counter_temp2=0


import queue
request_queue=queue.Queue(maxsize=500000)
insertion_time=datetime.now()


LAST_WHITELIST_FETCH = 0
WHITELIST_REFRESH_INTERVAL = 5  # seconds
WHITELIST_CACHE = set()

from scipy.stats import norm

# import os
# import re

# ENV_DIR = "securegate_files"
# ENV_FILE = "securegate.env"
# ENV_PATH = os.path.join(ENV_DIR, ENV_FILE)

# REQUIRED_FIELDS = {
#     "SECUREGATE_DB_HOST": {
#         "prompt": "Database host",
#         "example": "localhost"
#     },
#     "SECUREGATE_DB_PORT": {
#         "prompt": "Database port",
#         "example": "3306",
#         "validator": lambda x: x.isdigit() and 1 <= int(x) <= 65535
#     },
#     "SECUREGATE_DB_USER": {
#         "prompt": "Database username",
#         "example": "root"
#     },
#     "SECUREGATE_DB_PASS": {
#         "prompt": "Database password",
#         "example": "StrongPassword123"
#     },
#     "SECUREGATE_DB_NAME": {
#         "prompt": "Database name",
#         "example": "securegate"
#     },
#     "SECUREGATE_SMTP_HOST": {
#         "prompt": "SMTP host",
#         "example": "smtp.gmail.com"
#     },
#     "SECUREGATE_SMTP_PORT": {
#         "prompt": "SMTP port",
#         "example": "587",
#         "validator": lambda x: x.isdigit() and 1 <= int(x) <= 65535
#     },
#     "SECUREGATE_SMTP_USER": {
#         "prompt": "SMTP user email",
#         "example": "alerts@securegate.work.gd",
#         "validator": lambda x: re.match(r"[^@]+@[^@]+\.[^@]+", x)
#     },
#     "SECUREGATE_SMTP_PASS": {
#         "prompt": "SMTP password / app password",
#         "example": "AppPasswordHere"
#     },
#     "SECUREGATE_SECRET_KEY": {
#         "prompt": "SecureGate secret key",
#         "example": "random_long_secret_string_32_chars"
#     }
# }

# def ask_until_valid(key, meta):
#     while True:
#         value = input(f"{meta['prompt']}: ").strip()

#         if not value:
#             print(f"❌ Error: Value cannot be empty")
#             print(f"👉 Expected format example: {key}={meta['example']}\n")
#             continue

#         if "validator" in meta and not meta["validator"](value):
#             print(f"❌ Invalid value for {key}")
#             print(f"👉 Expected format example: {key}={meta['example']}\n")
#             continue

#         return value

# def create_or_complete_env():
#     if not os.path.isdir(ENV_DIR):
#         os.makedirs(ENV_DIR, exist_ok=True)

#     existing = {}

#     if os.path.exists(ENV_PATH):
#         with open(ENV_PATH, "r") as f:
#             for line in f:
#                 if "=" in line and not line.strip().startswith("#"):
#                     k, v = line.strip().split("=", 1)
#                     existing[k] = v

#     new_entries = []

#     print("\n🔐 SecureGate Environment Setup\n")

#     for key, meta in REQUIRED_FIELDS.items():
#         if key in existing and existing[key] and existing[key] != "CHANGE_ME":
#             continue  # already valid

#         print(f"[SETUP] {key}")
#         value = ask_until_valid(key, meta)
#         new_entries.append(f"{key}={value}")

#     if not os.path.exists(ENV_PATH):
#         with open(ENV_PATH, "w") as f:
#             f.write("# SecureGate Environment Configuration\n\n")

#     if new_entries:
#         with open(ENV_PATH, "a") as f:
#             for line in new_entries:
#                 f.write(line + "\n")

#         try:
#             if os.name != "nt":
#                 os.chmod(ENV_PATH, 0o600)
#         except Exception:
#             pass

#         print("\n✅ securegate.env updated successfully.")
#     else:
#         print("✅ All required values already exist. No changes needed.")

# # Call once at startup
# create_or_complete_env()


class SYS_INFO:
    global request,data
    def __init__(self, ips,request,iprequest,network_protocol,connection,cursor):
        self.ips=ips
        self.request=request
        self.iprequest=iprequest
        self.network_protocol_class=network_protocol
        self.connection=connection
        self.cursor=cursor
        
    @staticmethod
    def dbcreate():
            connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                port=3306,
            )
            cursor=connection.cursor()
        
            cursor.execute("CREATE DATABASE IF NOT EXISTS securegate")
            cursor.execute("USE securegate")
            #ip table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip (
            ip_address VARCHAR(45) PRIMARY KEY,
            request_time DATETIME,
            request_count INT DEFAULT 1,
            is_blocked BOOLEAN DEFAULT 0,
            is_local BOOLEAN DEFAULT 0
            ,block_time DATETIME,country VARCHAR(45)
            ,last_seen DATETIME)
            """)

        #request_type table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_type (
            port_number SMALLINT UNSIGNED PRIMARY KEY,
            port_name VARCHAR(50),
            request_count INT DEFAULT 1,               
            request_time DATETIME               
            ,last_seen DATETIME
                           )
            """)

            #ip_request_junction table
            cursor.execute("""
         CREATE TABLE IF NOT EXISTS iprequest_junction (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    -- Time
    request_time DATETIME,
                           
    -- Network identity
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    src_port SMALLINT UNSIGNED,
    dst_port SMALLINT UNSIGNED,
    protocol VARCHAR(10),
    interface_name VARCHAR(30),

    -- Transport details
    tcp_flags VARCHAR(10),
    ttl SMALLINT UNSIGNED,
    window_size INT,
    seq_num BIGINT,
    ack_num BIGINT,

    -- Packet metadata
    packet_length SMALLINT UNSIGNED,
    payload_size SMALLINT UNSIGNED,

    -- L2 / L3
    mac_src VARCHAR(17),
    mac_dst VARCHAR(17),
    ether_type VARCHAR(10),
    ip_flags VARCHAR(10),
    fragment_offset SMALLINT,

    -- ICMP / IPv6
    icmp_type TINYINT,
    icmp_code TINYINT,
    ipv6_flow_label INT,
    ipv6_traffic_class SMALLINT,


    INDEX(src_ip),
    INDEX(dst_ip),
    INDEX(protocol),
    INDEX(dst_port),
    INDEX(request_time)
)
            """)

            #all setting
            cursor.execute("""
            
CREATE TABLE IF NOT EXISTS settings (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    admin_name VARCHAR(50) ,
    password_hash VARCHAR(255) ,
    email VARCHAR(50),
    phone VARCHAR(13),

    request_time_limit INT,           -- in minutes
    max_requests_per_ip JSON,

    honeypot_ips VARCHAR(255),
    allowed_ports LONGTEXT,
    sensitive_folders VARCHAR(255),

    whitelisted_ips LONGTEXT NULL,
    blacklisted_ips LONGTEXT NULL,

    upload_folder VARCHAR(255),
    email_alerts_enabled BOOLEAN,
    email_token TEXT,
    sender_email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

                           )


""")
            cursor.execute("""CREATE TABLE IF NOT EXISTS network_protocol (
    
    protocol VARCHAR(10) NOT NULL PRIMARY KEY,  
    request_count INT DEFAULT 0,             
    first_seen DATETIME,                     
    last_seen DATETIME                       
    )""")
            

            cursor.execute("""
  CREATE TABLE IF NOT EXISTS attack_state (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    attack_type VARCHAR(30) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,

    first_detected DATETIME NOT NULL,
    last_detected DATETIME NOT NULL,

    hit_count INT DEFAULT 1,
    severity ENUM('LOW','MEDIUM','HIGH') DEFAULT 'LOW',

    actions_taken JSON NULL,
    action_expires_at DATETIME NULL,

    is_active BOOLEAN DEFAULT 1,

    UNIQUE KEY uniq_attack (attack_type, fingerprint),
    INDEX idx_src_ip (src_ip),
    INDEX idx_active (is_active),
    INDEX idx_expiry (action_expires_at)
)
""")

          




            print("All tables created successfully.")



                # First, checking if table has data so that jr future madhye user ne dilela data mule he change nay honar
            cursor.execute("SELECT max_requests_per_ip FROM settings")
            result = cursor.fetchone()

            if result == None:
                # Prepare default data
                timer = [1,2, 3, 4,5, 10, 20, 30]
                iprequestlimit = [150, 320, 430, 540, 650, 10000]
                di = dict(zip((timer),( iprequestlimit)))
                json_data = json.dumps(di)

                #Insert JSON into the table
                cursor.execute("SELECT COUNT(*) FROM settings")
                (count,) = cursor.fetchone()

                if count != 0:  # Only insert if table is empty
                    query = "INSERT INTO settings (max_requests_per_ip) VALUES (%s)"
                    cursor.execute(query, (json_data,))
                    connection.commit()









   

    
        # Continuously monitor network requests
    def monitor_requests(self):
        global counter_temp2
        log_file_path = "securegate_detailed_log2.json"
        remaining_lines = []
        try:
            if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 0:
                with open(log_file_path, "r") as f:
                    lines = f.readlines()

                for line in lines:
                    print(line)
                    counter_temp2+=1
                    print("counter temp2  ",counter_temp2)
                    print("Processing line:", line.strip())
                    line = line.strip()
                    try:
                        data = json.loads(line)  # Try to parse JSON data

                        request_queue.put(data)

                    except Exception as e:
                        print(f"Error parsing line: {line}\nReason: {e}")
                        remaining_lines.append(line + '\n')  

                #print("for loop chya baher")

                # After processing, overwrite file with error vale lines
                with open(log_file_path, "w") as f:
                    f.writelines(remaining_lines)

        except Exception as outer_error:
                print("Fatal error while reading/parsing log file:", outer_error)



           
    def process(self):
            global data,request_queue
            global insertion_time
            global WHITELIST_CACHE,LAST_WHITELIST_FETCH
           
            now = time.time()
            if now - LAST_WHITELIST_FETCH < WHITELIST_REFRESH_INTERVAL:
            
                try:
                    cursor = connection.cursor()
                    cursor.execute("SELECT whitelisted_ips FROM settings LIMIT 1")
                    row = cursor.fetchone()

                    if row and row[0]:
                        WHITELIST_CACHE = {
                            IPS.normalize_ip(ip)
                            for ip in row[0].split(",")
                            if IPS.normalize_ip(ip)
                        }
                    else:
                        WHITELIST_CACHE = set()

                    LAST_WHITELIST_FETCH = now
                    cursor.close()

                    # optional debug
                    # print("[INFO] Whitelist refreshed:", WHITELIST_CACHE)

                except Exception as e:
                    print("[WHITELIST REFRESH ERROR]:", e)





            #print("Processing")
            if not request_queue.empty():
                while not request_queue.empty():
                    try:
                        curr_request = request_queue.get(timeout=1)

                        time_str = curr_request.get("Time")
                        request_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S.%f")

                        # ---- Network identity ----
                        src_ip = str(curr_request.get("Src_IP"))
                        if src_ip in WHITELIST_CACHE:
                            continue
                        #ignoring whitelist ips
                        dst_ip = str(curr_request.get("Dst_IP"))

                        src_port = curr_request.get("Src_Port")
                        if src_port in ("N/A", "", None):
                            src_port=0
                        dst_port = curr_request.get("Dst_Port")
                        if dst_port in ("N/A", "", None):
                            dst_port =0
                        protocol = str(curr_request.get("Protocol"))
                        interface_name = str(curr_request.get("Interface"))

                        # ---- Transport details ----
                        tcp_flags = curr_request.get("Flags")
                        ttl = curr_request.get("TTL")
                        window_size = curr_request.get("Window")
                        seq_num = curr_request.get("Seq")
                        ack_num = curr_request.get("Ack")

                        # ---- Packet metadata ----
                        packet_length = curr_request.get("Packet_Length")
                        payload_size = curr_request.get("Payload_Size")

                        # ---- L2 / L3 ----
                        mac_src = curr_request.get("MAC_Src")
                        mac_dst = curr_request.get("MAC_Dst")
                        ether_type = curr_request.get("Ether_Type")
                        ip_flags = curr_request.get("IP_Flags")
                        fragment_offset = curr_request.get("Fragment_Offset")

                        # ---- ICMP / IPv6 ----
                        def na_to_null(value):
                            if value in ("N/A", "", "NA"):
                                return None
                            return value
                        icmp_type = na_to_null(curr_request.get("ICMP_Type"))
                        icmp_code = na_to_null(curr_request.get("ICMP_Code"))
                        ipv6_flow_label = na_to_null(curr_request.get("IPv6_FlowLabel"))
                        ipv6_traffic_class = na_to_null(curr_request.get("IPv6_TrafficClass"))

                        insertion_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S.%f")
                        try:
                            #print("checking wait")
                            self.ips.ins_ip(src_ip,time_str)
                            #print("ins_ip")                    
                            self.request.ins_request(dst_port,time_str)
                            #print("ins_request")
                            
                            self.iprequest.ins_iprequest(request_time,src_ip, dst_ip, src_port,
                             dst_port, protocol, interface_name,tcp_flags, ttl, window_size, seq_num,
                             ack_num,packet_length, payload_size,mac_src, mac_dst, ether_type,
                             ip_flags, fragment_offset,icmp_type, icmp_code,
                               ipv6_flow_label, ipv6_traffic_class
)
                            #print("ins_iprequest")
                            self.network_protocol_class.ins_network_protocol(protocol,time_str)
                            #print("ins_network_protocol")
                        except Exception as e:
                            print(e)
                    except queue.Empty:
                        print(queue.Empty)
                        continue
                    

    @staticmethod
    
    def is_connected_to_internet():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1) 
            sock.sendto(b'', ("8.8.8.8", 53))
            return True
        except Exception:
            return False
        finally:
            sock.close()
    @staticmethod
    def assign_country(conn,cursor):
        if sys_info.is_connected_to_internet:
            try:
                    while True: 
                        cursor.execute("""SELECT ip_address FROM ip WHERE country IS NULL LIMIT 100""")
                        country_ips = cursor.fetchall()
                        
                        if not country_ips:
                            time.sleep(10)
                            continue
                        else:
                            for ip_row in country_ips:
                                ip = ip_row[0]
                                country = ips.get_country(ip) 
                                #print("country \n")
                                cursor.execute("UPDATE ip SET country = %s WHERE ip_address = %s", (country, ip),multi=True)
                                conn.commit()
            
            except Exception as e:
                print("[Background thread error]:", e)
    @staticmethod
    def upsert_attack(cursor, attack_type, src_ip, fingerprint, severity):
        
        cursor.execute("""
        SELECT 1
        FROM attack_state
        WHERE attack_type = %s AND fingerprint = %s
            LIMIT 1
        """, (attack_type, fingerprint))

        exists = cursor.fetchone()

        if exists:
            cursor.execute("""
            UPDATE attack_state
            SET
                last_detected = NOW(),
                action_expires_at = NOW() + INTERVAL 15 MINUTE,
                is_active = 1
            WHERE attack_type = %s AND fingerprint = %s
            """, (attack_type, fingerprint))

            connection.commit()
        else:
            attacks = []
            # 1️⃣ EMAIL ALERT
            try:
                subject, message = EMERGENCY_ALERT.generate_email(
                    alert_type="intrusion",
                    data={
                        "ip": src_ip,
                        "time": datetime.now(),
                        "protocol": attack_type
                    }
                )
                EMERGENCY_ALERT.send_email_alert(subject, message)
                attacks.append("EMAIL_ALERT")
            except Exception as e:
                print("[EMAIL ALERT FAILED]", e)


            # 2️⃣ FILE UPLOAD
            try:
                EMERGENCY_ALERT.upload_sensitive_files_to_drive()
                attacks.append("FILE_UPLOAD")
            except Exception as e:
                print("[FILE UPLOAD FAILED]", e)

            if isinstance(src_ip, str) and "," in src_ip:
                # Multiple IPs
                for attacker_ip in src_ip.split(","):
                    attacker_ip = attacker_ip.strip()
                    if attacker_ip:
                        EMERGENCY_ALERT.honeypot_diversion(attacker_ip, divert=True)
                        attacks.append("HONEYPOT_DIVERT")
            else:
                # Single IP
                EMERGENCY_ALERT.honeypot_diversion(src_ip, divert=True)
                attacks.append("HONEYPOT_DIVERT")

            actions_json = json.dumps(attacks)
            query = """
            INSERT INTO attack_state
                (
                    attack_type,
                    src_ip,
                    fingerprint,
                    first_detected,
                    last_detected,
                    hit_count,
                    severity,
                    actions_taken,
                    action_expires_at,
                    is_active
                )
            VALUES
                (
                    %s, %s, %s,
                    NOW(), NOW(),
                    1,
                    %s,
                    %s,
                    NOW() + INTERVAL 15 MINUTE,
                    1
                )
            ON DUPLICATE KEY UPDATE
                last_detected = NOW(),
                hit_count = hit_count + 1,
                severity = VALUES(severity),
                actions_taken = VALUES(actions_taken),
                is_active = 1
            """

            cursor.execute(
                query,
                (
                    attack_type,
                    src_ip,
                    fingerprint,
                    severity,
                    actions_json
                )
            )
    def check_suspiciousness(self):
        global insertion_time,timer,ipreqlimit
        try:
            request.is_request_suspicious()

            cursor.execute("SELECT max_requests_per_ip from settings")
            result = cursor.fetchone()

            if result is not None:
                json_data = result[0]  # The JSON string
                reqpertime_dict = json.loads(json_data)  # Convert to Python dictionary

                for timer,ipreqlimit in reqpertime_dict.items():
        
                    time_ago = insertion_time - timedelta(minutes=int(timer))  #current time nako data insertion real time nahi honar so problem yenar
                    #print(time_ago)
                    self.cursor.execute("""
                            SELECT ip_address, COUNT(*) as ip_count
                            FROM iprequest_junction
                            WHERE request_time >= %s
                            GROUP BY ip_address
                        """, (time_ago,))
                    ip_counts = self.cursor.fetchall()

                    

                    
                        # Group by Port
                    self.cursor.execute("""
                        SELECT port_number, COUNT(*) as port_count
                        FROM iprequest_junction
                        WHERE request_time >= %s
                        GROUP BY port_number
                    """, (time_ago,))
                    port_counts = self.cursor.fetchall()


                        # Group by Protocol
                    self.cursor.execute("""
                        SELECT protocol, COUNT(*) as network_protocol_count
                        FROM iprequest_junction
                        WHERE request_time >= %s
                        GROUP BY port_number
                    """, (time_ago,))
                    network_protocol_counts = self.cursor.fetchall()


                    # Total count of all requests 
                    self.cursor.execute("""
                        SELECT COUNT(*) FROM iprequest_junction WHERE request_time >= %s
                    """, (time_ago,))
                    total_requests = self.cursor.fetchone()[0]
    
                    for x in ip_counts:
                        if len(x) == 2:        
                                self.checkblk("ip",x,int(ipreqlimit),timer)
                    for x in port_counts:
                        if len(x) == 2:
                            self.checkblk("port",x,int(ipreqlimit),timer)
                    

                    #network protocol
                    for x in network_protocol_counts:
                        if len(x) == 2:
                            self.checkblk("network_protocol",x,int(ipreqlimit),timer)
                    


                    # total_requests:
                    self.checkblk("iprequest",total_requests,int(timer),timer)
                #unblock time
        

                self.cursor.execute("""
                SELECT ip_address, block_time FROM ip WHERE is_blocked = 1 AND block_time <= %s
                """, (datetime.now(),))
                rows = self.cursor.fetchall()
                for ip in rows:
                    print(ip[0])
                    self.ips.unblock_ip(ip[0])
                
                
        except Exception as e:
                print(e)
    #attack checking starts from here::::::::::::

        PORT_THRESHOLD = 25
        high_sev_port=100
        MIN_PACKETS = 50
        mass_scan_ports=1000
        SYN_RATIO_THRESHOLD = 0.4  #if more than 40% are syn packets then syn attack
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

        # ================= PORT SCAN =================
        ip_ports = defaultdict(set)   #unique port per ip

        for pkt in detection_packets:
            if pkt["dst_port"] is not None:
                ip_ports[pkt["src_ip"]].add(pkt["dst_port"])

        for ip, ports in ip_ports.items():
            if len(ports) >= PORT_THRESHOLD:
                fingerprint = f"{ip}:PORT_SCAN"
                severity = "MEDIUM" if len(ports) < high_sev_port else "HIGH"

                SYS_INFO.upsert_attack(
                    cursor,
                    attack_type="PORT_SCAN",
                    src_ip=ip,
                    fingerprint=fingerprint,
                    severity=severity
                )

        # ================= MASS SCAN =================
        all_ports = set()
        for ports in ip_ports.values():
            all_ports.update(ports)

        if len(all_ports) >= mass_scan_ports:
            for ip in ip_ports.keys():
                fingerprint = f"{ip}:MASS_SCAN"
                SYS_INFO.upsert_attack(
                    cursor,
                    attack_type="MASS_SCAN",
                    src_ip=ip,
                    fingerprint=fingerprint,
                    severity="HIGH"
                )

        # ================= SYN FLOOD =================
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
                fingerprint = f"{ip}:SYN_FLOOD"
                severity = "HIGH"

                SYS_INFO.upsert_attack(
                    cursor,
                    attack_type="SYN_FLOOD",
                    src_ip=ip,
                    fingerprint=fingerprint,
                    severity=severity
                )
        connection.commit()






    def checkblk(self,option,ipdata,limit,time_interval):
       
        
        if option=="ip":
            ip=ipdata[0]
            req_count=ipdata[1]
            print(req_count)
            print("/n")
            if  ips.is_ip_suspicious(req_count,limit):         #req>limit:
                reqps=int(((req_count-limit)/limit)*100)
                ips.block_ip(ip,reqps)
                print("IP BLOCK:-",ip)
            print("debug")
        '''if option=="port":
            port,port_request=req
            if request.is_port_suspicious(port_request,limit):
                request.securegate_response(port,port_request,limit)
            
            if option=="iprequest":
                count=ip
                if iprequest.is_iprequest_suspicious(count,limit):
                    iprequest.securegate_response(ipdata,limit,time_interval)        
            if option=="network_protocol":
                count=ip
                if network_protocol.is_iprequest_suspicious(count,limit):
                    network_protocol.securegate_response(ipdata,limit,time_interval)        
            '''
        

        cursor.execute("""
    SELECT
        id,
        src_ip,
        actions_taken
    FROM attack_state
    WHERE
        is_active = 1
        AND action_expires_at < NOW()
        """)

        expired_attacks = cursor.fetchall()
        
        for attack_id, attacker_ip, actions_json in expired_attacks:
            actions = json.loads(actions_json)

            # 🔁 Honeypot revert
            if "HONEYPOT_DIVERT" in actions:
                try:
                    EMERGENCY_ALERT.honeypot_diversion(attacker_ip, divert=False)
                except Exception as e:
                    print("[HONEYPOT REVERT FAILED]", e)

            # 🔁 File restore
            if "FILE_UPLOAD" in actions:
                try:
                    EMERGENCY_ALERT.restore_permissions()  # or your restore logic
                except Exception as e:
                    print("[FILE RESTORE FAILED]", e)

            if "BLOCK_IP" in actions:
                try:
                    cursor.execute("""
                        SELECT is_blocked, block_time
                        FROM ip
                        WHERE ip_address = %s
                        LIMIT 1
                    """, (attacker_ip,))

                    row = cursor.fetchone()

                    if row:
                        is_blocked, block_time = row

                        # Unblock ONLY if block time expired
                        if is_blocked == 1 and block_time and block_time <= datetime.now():
                            IPS.unblock_ip(attacker_ip)
                        else:
                            # Still blocked due to other reasons
                            pass

                except Exception as e:
                    print("[IP UNBLOCK CHECK FAILED]", e)

















class IPS:        
    #for ips
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        
    def ins_ip(self,ip,time):
        global counter_temp
        try:    
                #print("Ip is :-",ip,"    time is   ",time)
                query = """ INSERT INTO ip (ip_address,request_time,last_seen) VALUES (%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                request_count = request_count + 1,
                last_seen = VALUES(request_time)
                """
                self.cursor.execute(query, (ip,time,time,))  
                self.connection.commit()
                counter_temp+=1
                print("counter is :-",counter_temp)
                #print("ins ip completed")
        except Exception as e:
            print("error insertion :-",e)
     
    def block_ip(self,ip_address,blkps):

        cursor.execute("SELECT whitelisted_ips FROM settings LIMIT 1")
        result = cursor.fetchone()

        if not result or not result[0]:
            return 

        whitelist = result[0].split(",")  # CSV → list

    
        whitelist = [x.strip() for x in whitelist if x.strip()]

       
        if ip_address in whitelist:
            print(f"[BLOCKED SECTION:] {ip_address} is whitelisted, unblocked.")
            return

        block_list=self.block_list()
        if ip_address not in block_list:
            try:
                
                #if not self.loopback(ip_address):
                    blkmin=int(blkps+blkps*10/100)
                    blocktime= datetime.now()+ timedelta(minutes=blkmin)
                    print("Blocktime type:", type(blocktime))
                    print("IP:", repr(ip_address))
                    cursor = self.connection.cursor()
                    #subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)    
                    #subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"],check=True)
                    #  IP table
                    self.cursor.execute(
                    "UPDATE `IP` SET is_blocked = 1, block_time=%s WHERE `ip_address`=%s",
                    (blocktime, ip_address)
                    )
                    self.connection.commit()
                    print("Rows affected:", self.cursor.rowcount)
                    print(f"IP {ip_address} has been blocked in all tables.")

            except Exception as e:
                print(f"Error blocking IP: {e}")

    def unblock_ip(self,ip_address):
        try:
            global connection
            cursor = connection.cursor()
            #subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            #subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"],check=False)
            #  IP table
            query = """UPDATE ip 
                   SET is_blocked = 0, block_time = NULL 
                   WHERE ip_address = %s"""
            self.cursor.execute(query, (ip_address,))
            connection.commit()
      
        except Exception as e:
            print(f"Error blocking IP: {e}")    
    
            
    def get_country(self,ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            return data.get("country", "Unknown")
        except Exception as e:
            print(f"Error: {str(e)}")
    
        
    def loopback(self,x):
        loopback=["127.0.0.1",":::1","N/A"]
        if x in loopback:
            return True
        else :
            False
    
    def whitelist_ips(self):
        cursor = None
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT whitelisted_ips FROM settings LIMIT 1")
            row = cursor.fetchone()

            if not row or not row[0]:
                return set()

            # Convert CSV → set
            return {ip.strip() for ip in row[0].split(",") if ip.strip()}

        except Exception as e:
            print("[WHITELIST ERROR]:", e)
            return set()

        finally:
            if cursor:
                cursor.close()
        
    def block_list(self):
        cursor = None
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT ip_address FROM ip WHERE is_blocked = 1")
            return {row[0] for row in cursor.fetchall()}

        except Exception as e:
            print("[BLACKLIST ERROR]:", e)
            return set()

        finally:
            if cursor:
                cursor.close()
     
    
    def is_ip_suspicious(self,request_counter, expected_requests, confidence_level=0.99):

        print(f"request counter {request_counter} expected_request {expected_requests}  confidence_level: {confidence_level} ")
        std_dev = 0.1 * expected_requests  # 10% of expected as proxy Standardd deviation

        if std_dev == 0:
            return False

        z_score = (request_counter - expected_requests) / std_dev
        z_threshold = norm.ppf(confidence_level)

        return z_score > z_threshold
    
    def whitelist_ip(action, ip=None):
        try:
            cursor.execute("SELECT whitelisted_ips FROM settings LIMIT 1")
            result = cursor.fetchone()

            # Handle NULL or empty
            current_ips = result[0] if result else None

            # Convert bytes → str
            if isinstance(current_ips, bytes):
                current_ips = current_ips.decode()

            # Convert string → list
            if current_ips:
                ip_list = [x.strip() for x in current_ips.split(",") if x.strip()]
            else:
                ip_list = []

            # --------------------
            # ADD
            # --------------------
            if action == "add" and ip:
                if ip not in ip_list:
                    ip_list.append(ip)
                    print(f"[WHITELIST] Added: {ip}")
                else:
                    print(f"[WHITELIST] Already exists: {ip}")

            # --------------------
            # REMOVE
            # --------------------
            elif action == "remove" and ip:
                if ip in ip_list:
                    ip_list.remove(ip)
                    print(f"[WHITELIST] Removed: {ip}")
                else:
                    print(f"[WHITELIST] IP not found: {ip}")

            # --------------------
            # SHOW ALL
            # --------------------
            elif action == "all":
                return ip_list

            # --------------------
            # Save back to DB
            # --------------------
            final_text = ",".join(ip_list) if ip_list else None  # NULL instead of ''

            cursor.execute(
                "UPDATE settings SET whitelisted_ips=%s",
                (final_text,)
            )
            connection.commit()

        except Exception as e:
            print("[WHITELIST ERROR]:", e)

    def blacklist_ip(action, ip=None):
        cursor = None
        try:
            cursor = connection.cursor()

            cursor.execute("SELECT blacklisted_ips FROM settings LIMIT 1")
            result = cursor.fetchone()

            raw = result[0] if result and result[0] else "[]"
            if isinstance(raw, bytes):
                raw = raw.decode()

            try:
                ip_list = json.loads(raw)
            except Exception:
                ip_list = []

            if action == "add" and ip:
                if ip not in ip_list:
                    ip_list.append(ip)

            elif action == "remove" and ip:
                if ip in ip_list:
                    ip_list.remove(ip)

            elif action == "all":
                return ip_list  # ✅ ALWAYS list

            final_json = json.dumps(ip_list)
            cursor.execute(
                "UPDATE settings SET blacklisted_ips=%s",
                (final_json,)
            )
            connection.commit()

            return ip_list  # ✅ return updated list

        except Exception as e:
            print("[BLACKLIST ERROR]:", e)
            return []        # ✅ NEVER None

    
    def normalize_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return str(ip)   # canonical form
        except ValueError:
            return None



class REQUEST:
    
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        
    
    def ins_request(self,request,time):
        #---ata vrchi request_time chi value ithe assign  hoil
        print(request,time)
        if request in ("N/A", "", None):
            request =0
        query = """ INSERT INTO request_type (port_number,request_time,last_seen) VALUES (%s,%s,%s)
        ON DUPLICATE KEY UPDATE
    request_count = request_count + 1,
    last_seen = VALUES(request_time)
        """
        self.cursor.execute(query, (request,time,time))  
        self.connection.commit()



    def is_request_suspicious(self):
        try:
            suspicious_percent = 20
            minimum_request = 100

            # -------------------------------------------------------
            # 1. Fetch allowed ports from settings
            # -------------------------------------------------------
            self.cursor.execute("SELECT allowed_ports FROM settings LIMIT 1")
            res = self.cursor.fetchone()

            if not res or not res[0]:
                print("[ERROR] No allowed ports found in DB.")
                return False

            # allowed_ports is stored as CSV: "22,80,443"
            valid_ports = {
                int(p.strip())
                for p in res[0].split(",")
                if p.strip().isdigit()
            }
            print("Valid Ports:", valid_ports)

            # -------------------------------------------------------
            # 2. Get last 1 hour requests
            # -------------------------------------------------------
            one_hour_ago = datetime.now() - timedelta(hours=1)

            self.cursor.execute("""
                SELECT port, request_time 
                FROM iprequest 
                WHERE request_time >= %s
            """, (one_hour_ago,))

            logs = self.cursor.fetchall()

            if not logs:
                print("[INFO] No requests found in last 1 hour.")
                return False

            total_requests = len(logs)
            print(f"Total Requests (1 hour): {total_requests}")

            # -------------------------------------------------------
            # 3. Ignore detection if traffic too low
            # -------------------------------------------------------
            if total_requests <= minimum_request:
                print("[INFO] Not enough traffic (< minimum threshold).")
                return False

            # -------------------------------------------------------
            # 4. Count invalid port requests
            # -------------------------------------------------------
            invalid_count = 0

            for row in logs:
                port = int(row[0])  # row[0] = port (tuple index)
                if port not in valid_ports:
                    invalid_count += 1

            print("Invalid Port Requests:", invalid_count)

            # -------------------------------------------------------
            # 5. Calculate invalid percentage
            # -------------------------------------------------------
            percent_invalid = (invalid_count / total_requests) * 100
            print(f"Invalid %: {percent_invalid:.2f}%")

            # -------------------------------------------------------
            # 6. Compare & return result
            # -------------------------------------------------------
            if percent_invalid >= suspicious_percent:
                print("[ALERT] Suspicious traffic detected!")
                return True

            return False

        except Exception as e:
            print("[ERROR in suspicious check]:", e)
            return False



    def securegate_response(protocol,limit,time_interval):
        pass        
                   
           








     
class IPREQUEST:
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor

    def ins_iprequest(
        self,
        request_time,
        src_ip, dst_ip, src_port, dst_port, protocol, interface_name,
        tcp_flags, ttl, window_size, seq_num, ack_num,
        packet_length, payload_size,
        mac_src, mac_dst, ether_type, ip_flags, fragment_offset,
        icmp_type, icmp_code, ipv6_flow_label, ipv6_traffic_class
    ):
        try:
            def clean(v):
                return None if v in ("", "N/A", "NA", None) else v

            src_port = clean(src_port)
            dst_port = clean(dst_port)
            ttl = clean(ttl)
            window_size = clean(window_size)
            seq_num = clean(seq_num)
            ack_num = clean(ack_num)
            packet_length = clean(packet_length)
            payload_size = clean(payload_size)
            fragment_offset = clean(fragment_offset)
            icmp_type = clean(icmp_type)
            icmp_code = clean(icmp_code)
            ipv6_flow_label = clean(ipv6_flow_label)
            ipv6_traffic_class = clean(ipv6_traffic_class)

            src_ip = clean(src_ip)
            dst_ip = clean(dst_ip)
            protocol = clean(protocol)
            interface_name = clean(interface_name)
            tcp_flags = clean(tcp_flags)
            mac_src = clean(mac_src)
            mac_dst = clean(mac_dst)
            ether_type = clean(ether_type)
            ip_flags = clean(ip_flags)

            query = """
            INSERT INTO iprequest_junction (
                request_time,
                src_ip, dst_ip, src_port, dst_port, protocol, interface_name,
                tcp_flags, ttl, window_size, seq_num, ack_num,
                packet_length, payload_size,
                mac_src, mac_dst, ether_type, ip_flags, fragment_offset,
                icmp_type, icmp_code, ipv6_flow_label, ipv6_traffic_class
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,
                %s,%s,
                %s,%s,%s,%s,%s,
                %s,%s,%s,%s
            )
            """

            values = (
                request_time,
                src_ip, dst_ip, src_port, dst_port, protocol, interface_name,
                tcp_flags, ttl, window_size, seq_num, ack_num,
                packet_length, payload_size,
                mac_src, mac_dst, ether_type, ip_flags, fragment_offset,
                icmp_type, icmp_code, ipv6_flow_label, ipv6_traffic_class
            )

            self.cursor.execute(query, values)
            self.connection.commit()

        except Exception as e:
            print("[DB INSERT ERROR]", e)


    
    def is_iprequest_suspicious(count,limit):
            pass
    def securegate_response(ipdata,limit,time_interval):        
            pass 

    
    '''
    def checking(self,ip,request):
        query = """ select * from iprequest_junction WHERE ip_address=%s and port_number = %s    """
        self.cursor.execute(query,(ip,request,))
        
        a=self.cursor.fetchall() 
        #print("\n incremented here",a,"\n")

'''



    
            



class NETWORK_PROTOCOL:
    
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
    

    def ins_network_protocol(self,request,time):
        print(request,time)
        #---ata vrchi request_time chi value ithe assign  hoil
        query = """ INSERT INTO network_protocol(protocol,first_seen,last_seen) VALUES (%s,%s,%s)
    ON DUPLICATE KEY UPDATE
    request_count = request_count + 1,
    last_seen = VALUES(first_seen)
        
        """
        self.cursor.execute(query, (request,time,time,))
        self.connection.commit()

    
    '''
    def fetch_network_protocol(self):
        try:
            cursor = self.connection.cursor()
            query = "SELECT types FROM network_protocol"
            self.cursor.execute(query)
            result = self.cursor.fetchall()
            if not result:
                return []
            return result
        except Exception:
           return [] 
    '''
    def is_request_suspicious(count,limit):
        pass
    def securegate_response(network_protocol,limit,time_interval):
        pass     



#import sendgrid
#from sendgrid.helpers.mail import Mail, Email, To, Content


import platform

# Get the OS name (e.g., 'Windows', 'Linux', 'Darwin' (for macOS))
os_name = platform.system()
print(f"Operating System: {os_name}")


class EMERGENCY_ALERT:
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
    
    def generate_email(alert_type, data=None):
        if data is None:
            data = {}

        if alert_type == "intrusion":
            subject = "⚠️ Intrusion Alert - Suspicious Activity Detected"
            message = (
                f"Suspicious activity detected on your SecureGate system.\n"
                f"Source IP: {data.get('ip', 'Unknown')}\n"
                f"Detected at: {data.get('time', 'Unknown')}\n"
                f"Request Type: {data.get('protocol', 'Unknown')}\n\n"
                f"Recommended Action: Review the logs immediately."
            )

        elif alert_type == "ip_block":
            subject = f"🚫 IP Blocked - {data.get('ip', 'Unknown')}"
            message = (
                f"The following IP has been blocked for exceeding limits:\n"
                f"IP Address: {data.get('ip', 'Unknown')}\n"
                f"Blocked at: {data.get('time', 'Unknown')}\n"
                f"Reason: {data.get('reason', 'Too many requests')}\n\n"
                f"Check SecureGate logs for more details."
            )

        elif alert_type == "honeypot_trigger":
            subject = f"🐍 Honeypot Triggered - {data.get('ip', 'Unknown')}"
            message = (
                f"Honeypot diversion triggered for IP: {data.get('ip', 'Unknown')}\n"
                f"Timestamp: {data.get('time', 'Unknown')}\n"
                f"Redirected to: {data.get('honeypot_ip', 'Unknown')}\n\n"
                f"SecureGate is monitoring attacker behavior."
            )

        else:
            subject = "📢 SecureGate Notification"
            message = f"An event has occurred:\n{data}"

        return subject, message


    # ✅ Function to Fetch Email Data (API Token, Sender, Receiver)
    def get_email(role):
        try:
            if role == "sender":
                cursor.execute("SELECT email_token, sender_email FROM settings LIMIT 1")
                result = cursor.fetchone()
               
                if result:
                    return result  # (token, sender_email)
                else:
                    print("[!] No sender token/email found.")
                    return None

            elif role == "receiver":
                cursor.execute("SELECT email FROM settings LIMIT 1")
                result = cursor.fetchone()
              
                if result and result[0]:
                    return result[0]
                else:
                    print("[!] No receiver email found.")
                    return None

            else:
                print("[!] Invalid argument: use 'sender' or 'receiver'")
                return None

        except Exception as e:
            print(f"[!] Database error: {e}")
            return None


    # ✅ Function to Send Email via MailerSend API
    def send_email_alert(subject, message):
        try:
            email_info = EMERGENCY_ALERT.get_email("sender")
            if not email_info:
                print("[!] Cannot fetch sender info from DB.")
                return

            token, sender_email = email_info
            receiver_email = EMERGENCY_ALERT.get_email("receiver") or sender_email  # fallback to sender

            if not token:
                print("[!] Missing MailerSend API token in database.")
                return

            ms = MailerSendClient(api_key=token)

            # --- Build Email ---
            email = (
                EmailBuilder()
                .from_email("alerts@securegate.work.gd", "SecureGate System")  # verified domain
                .to_many([{"email": receiver_email, "name": "Admin"}])
                .subject(subject)
                .html(f"<h3>{subject}</h3><p>{message}</p>")
                .text(message)
                .build()
            )

            # --- Send Email ---
            response = ms.emails.send(email)
            print("[+] Email sent successfully via MailerSend!")
            print("Response:", response)

        except Exception as e:
            print(f"[!] Failed to send email: {e}")


    def upload_sensitive_files_to_drive():
        try:
            cursor.execute("SELECT upload_folder, sensitive_folders FROM settings LIMIT 1")
            result = cursor.fetchone()
            if not result: 
                print("[!] No folder paths found in database.")
                return

            upload_folder, sensitive_folder = result
            if not upload_folder or not sensitive_folder:

                print(" Missing upload or sensitive folder path.")
                return


            try:
                cmd = ["rclone", "copy", sensitive_folder, upload_folder]
                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode == 0:
                    print("[UPLOAD SUCCESS]", sensitive_folder)
                else:
                    
                    print("[UPLOAD ERROR]", result.stderr)

            except Exception as e:
                print("[EXCEPTION]", e)
            
            print(f"[+] All sensitive files uploaded to '{upload_folder}' successfully!")

            if os.path.isfile(sensitive_folder):
                try:
                    os.remove(sensitive_folder)
                    print(f"[SECURE] File deleted: {sensitive_folder}")
                except Exception as e:
                    print(f"[ERROR] Unable to delete file: {e}")
            else:
                print(f"[INFO] File not found: {sensitive_folder}")

        except Exception as e:
            print(f"[!] Error: {e}")  

    def honeypot_diversion(attacker_ip,divert):
        port=4444
        os_name = platform.system()
        try:
            cursor.execute("SELECT honeypot_ips FROM settings LIMIT 1")
            row = cursor.fetchone()

            if not row or not row[0]:
                return None

            honeypot_ip= row[0].split(",")[0].strip()
        except:
            print("Honeypot not found")
        
        if divert:
            # ---------------- ADD DIVERSION ----------------
            if os_name == "Linux":
                subprocess.run(
                    [
                        "iptables", "-t", "nat", "-A", "PREROUTING",
                        "-s", attacker_ip,
                        "-j", "DNAT", "--to-destination", honeypot_ip
                    ],
                    check=True
                )

            elif os_name == "Windows":
                subprocess.run(
                    [
                        "netsh", "interface", "portproxy", "add", "v4tov4",
                        "listenaddress=0.0.0.0",
                        f"listenport={port}",
                        f"connectaddress={honeypot_ip}",
                        f"connectport={port}"
                    ],
                    shell=True,
                    check=True
                )

            else:
                print("Unsupported OS:", os_name)

        else:
            # ---------------- UNDO DIVERSION ----------------
            if os_name == "Linux":
                subprocess.run(
                    [
                        "iptables", "-t", "nat", "-D", "PREROUTING",
                        "-s", attacker_ip,
                        "-j", "DNAT", "--to-destination", honeypot_ip
                    ],
                    check=True
                )

            elif os_name == "Windows":
                subprocess.run(
                    [
                        "netsh", "interface", "portproxy", "delete", "v4tov4",
                        "listenaddress=0.0.0.0",
                        f"listenport={port}"
                    ],
                    shell=True,
                    check=True
                )

            else:
                print("Unsupported OS:", os_name)



























from collections import defaultdict
from datetime import datetime
import mysql.connector

   







SYS_INFO.dbcreate()
db_name="securegate"



connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                port=3306,
                database=db_name
            )

cursor=connection.cursor(buffered=True)  # fetch kelela data read tevhach kela pahije as kahi nahi so he vapraych
ips=IPS(connection,cursor)
SYS_INFO.dbcreate()

request=REQUEST(connection,cursor)
iprequest=IPREQUEST(connection,cursor)
network_protocol=NETWORK_PROTOCOL(connection,cursor)
sys_info=SYS_INFO(ips,request,iprequest,network_protocol,connection,cursor)

RUN_ENGINE=True
if __name__ == "__main__" and RUN_ENGINE:
    while True:
        print("monitor request")
        sys_info.monitor_requests()
        print("process")
        sys_info.process()
        
        print("check suspiciousness")
        sys_info.check_suspiciousness()
        
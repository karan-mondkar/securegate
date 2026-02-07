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
import resend


from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

counter_temp=0
counter_temp2=0





# =========================================
# SecureGate Global Configuration Loader
# =========================================

import os
import sys
from dotenv import load_dotenv



import os
import time
import traceback

import sys
from dotenv import load_dotenv

def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)  # EXE folder
    return os.path.dirname(os.path.abspath(__file__))  # .py folder

BASE_DIR = get_base_dir()

ENV_FILE = os.path.join(BASE_DIR, "securegate.env")

if not os.path.exists(ENV_FILE):
    raise RuntimeError(f"securegate.env not found at {ENV_FILE}")

load_dotenv(ENV_FILE)



def log_error(message, exc=None):
    """
    Appends error message to securegate_error.log.
    File is created automatically if it does not exist.
    """
    try:
        LOG_FILE = os.path.join(BASE_DIR, "securegate_error.log")
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
        # Never crash the service due to logging failure
        pass

# -------------------------------------------------
# REQUIRED CONFIG FIELDS + DEFAULTS
# -------------------------------------------------
REQUIRED_ENV = {
    # ---- Database ----
    "SECUREGATE_DB_HOST": "localhost",
    "SECUREGATE_DB_PORT": "3306",
    "SECUREGATE_DB_USER": "root",
    "SECUREGATE_DB_PASS": "",
    "SECUREGATE_DB_NAME": "securegate",

    # ---- Performance ----
    "SECUREGATE_QUEUE_MAXSIZE": "500000",
    "SECUREGATE_PACKET_QUEUE_SIZE": "50000",
    "SECUREGATE_WHITELIST_REFRESH_INTERVAL": "5",

    # ---- Blocking ----
    "SECUREGATE_BLOCK_TIME_BUFFER_PERCENT": "10",

    # ---- Detection ----
    "SECUREGATE_PORT_SCAN_THRESHOLD": "25",
    "SECUREGATE_HIGH_SEVERITY_PORTS": "100",
    "SECUREGATE_MIN_PACKETS": "50",
    "SECUREGATE_MASS_SCAN_PORTS": "1000",
    "SECUREGATE_SYN_RATIO_THRESHOLD": "0.4",

    # ---- Network / APIs ----
    "SECUREGATE_GEOIP_API": "http://ip-api.com/json",
    "SECUREGATE_INTERNET_TEST_IP": "8.8.8.8",
    "SECUREGATE_INTERNET_TEST_PORT": "53",

    # ---- Packet Capture ----
    "SECUREGATE_INTERFACE": "eth0",
    "SECUREGATE_LOG_COPY_INTERVAL": "3",

    # ---- Files ----
    "SECUREGATE_LOG_FILE_STAGE1": "securegate_detailed_log1.json",
    "SECUREGATE_LOG_FILE_STAGE2": "securegate_detailed_log2.json",
    "SECUREGATE_LOG_FILE_IMPORTANT": "imp_detailed_log.json",
    "SECUREGATE_KEY_FILE": "securegate.key",

    # ---- GUI ----
    "SECUREGATE_GUI_REFRESH_INTERVAL": "10",
    "SECUREGATE_GUI_ROWS_PER_PAGE": "15",
    "SECUREGATE_GUI_WIDTH": "1100",
    "SECUREGATE_GUI_HEIGHT": "700",
    "SECUREGATE_GUI_ICON": "securegate_image.ico",
    "SECUREGATE_GUI_BANNER": "securegate_.png",
    "SECUREGATE_GUI_THEME": "arc"
}

def resolve_log_path(log_filename):
    path = os.path.join(BASE_DIR, log_filename)
    os.makedirs(BASE_DIR, exist_ok=True)
    open(path, "a").close()
    return path

def build_db_config(allow_no_db=False):
    config = {
        "host": SECUREGATE_DB_HOST,
        "user": SECUREGATE_DB_USER,
        "password": SECUREGATE_DB_PASS,
        "port": SECUREGATE_DB_PORT,
    }

    if not allow_no_db:
        config["database"] = SECUREGATE_DB_NAME

    return config


# -------------------------------------------------
# VALIDATE ENV FILE CONTENT
# -------------------------------------------------
def validate_env():
    errors = []

    for key in REQUIRED_ENV:
        value = os.getenv(key)

        # ---------- Missing / Empty ----------
        if (value is None or value.strip() == "") and key != "SECUREGATE_DB_PASS":
            errors.append(f"Missing or empty value: {key}")
            continue

        if value is None:
            continue

        value = value.strip()

        # ---------- Integer fields ----------
        if key.endswith("_PORT") or "SIZE" in key or "INTERVAL" in key:
            try:
                int(value)
            except ValueError as e:
                log_error("Engine crashed during startup", e)
                errors.append(f"Invalid integer value for {key}: {value}")

        # ---------- Float field ----------
        if key == "SECUREGATE_SYN_RATIO_THRESHOLD":
            try:
                float(value)
            except ValueError as e:
                log_error("Engine crashed during startup", e)
                errors.append(f"Invalid float value for {key}: {value}")

    if errors:
        print("\n❌ CONFIGURATION ERRORS DETECTED:\n")
        for err in errors:
            print(f"   • {err}")
        print("\n🛑 Fix securegate.env and restart SecureGate\n")
        sys.exit(1)   # ✅ MUST EXIT

# -------------------------------------------------
# MAIN CONFIG LOADER
# -------------------------------------------------

def load_securegate_config():
    global INTERFACE_NAME
    global SECUREGATE_DB_HOST, SECUREGATE_DB_PORT, SECUREGATE_DB_USER, SECUREGATE_DB_PASS, SECUREGATE_DB_NAME
    global SECUREGATE_QUEUE_MAXSIZE, SECUREGATE_PACKET_QUEUE_SIZE, SECUREGATE_WHITELIST_REFRESH_INTERVAL
    global SECUREGATE_BLOCK_TIME_BUFFER_PERCENT
    global SECUREGATE_PORT_SCAN_THRESHOLD, SECUREGATE_HIGH_SEVERITY_PORTS
    global SECUREGATE_MIN_PACKETS, SECUREGATE_MASS_SCAN_PORTS, SECUREGATE_SYN_RATIO_THRESHOLD
    global SECUREGATE_GEOIP_API, SECUREGATE_INTERNET_TEST_IP, SECUREGATE_INTERNET_TEST_PORT
    global SECUREGATE_LOG_COPY_INTERVAL
    global SECUREGATE_LOG_FILE_STAGE1, SECUREGATE_LOG_FILE_STAGE2, SECUREGATE_LOG_FILE_IMPORTANT, SECUREGATE_KEY_FILE
    global SECUREGATE_GUI_REFRESH_INTERVAL, SECUREGATE_GUI_ROWS_PER_PAGE
    global SECUREGATE_GUI_WIDTH, SECUREGATE_GUI_HEIGHT
    global SECUREGATE_GUI_ICON, SECUREGATE_GUI_BANNER, SECUREGATE_GUI_THEME

  

    # Step 2: Load env
    load_dotenv(ENV_FILE)

    # Step 3: Validate
    validate_env()

    # Step 4: Assign values
    INTERFACE_NAME = os.getenv("SECUREGATE_INTERFACE")

    SECUREGATE_DB_HOST = os.getenv("SECUREGATE_DB_HOST")
    SECUREGATE_DB_PORT = int(os.getenv("SECUREGATE_DB_PORT",0))
    SECUREGATE_DB_USER = os.getenv("SECUREGATE_DB_USER")
    SECUREGATE_DB_PASS = os.getenv("SECUREGATE_DB_PASS")
    SECUREGATE_DB_NAME = os.getenv("SECUREGATE_DB_NAME")

    SECUREGATE_QUEUE_MAXSIZE = int(os.getenv("SECUREGATE_QUEUE_MAXSIZE"))
    SECUREGATE_PACKET_QUEUE_SIZE = int(os.getenv("SECUREGATE_PACKET_QUEUE_SIZE"))
    SECUREGATE_WHITELIST_REFRESH_INTERVAL = int(os.getenv("SECUREGATE_WHITELIST_REFRESH_INTERVAL"))

    SECUREGATE_BLOCK_TIME_BUFFER_PERCENT = int(os.getenv("SECUREGATE_BLOCK_TIME_BUFFER_PERCENT"))

    SECUREGATE_PORT_SCAN_THRESHOLD = int(os.getenv("SECUREGATE_PORT_SCAN_THRESHOLD"))
    SECUREGATE_HIGH_SEVERITY_PORTS = int(os.getenv("SECUREGATE_HIGH_SEVERITY_PORTS"))
    SECUREGATE_MIN_PACKETS = int(os.getenv("SECUREGATE_MIN_PACKETS"))
    SECUREGATE_MASS_SCAN_PORTS = int(os.getenv("SECUREGATE_MASS_SCAN_PORTS"))
    SECUREGATE_SYN_RATIO_THRESHOLD = float(os.getenv("SECUREGATE_SYN_RATIO_THRESHOLD"))

    SECUREGATE_GEOIP_API = os.getenv("SECUREGATE_GEOIP_API")
    SECUREGATE_INTERNET_TEST_IP = os.getenv("SECUREGATE_INTERNET_TEST_IP")
    SECUREGATE_INTERNET_TEST_PORT = int(os.getenv("SECUREGATE_INTERNET_TEST_PORT"))

    SECUREGATE_LOG_COPY_INTERVAL = int(os.getenv("SECUREGATE_LOG_COPY_INTERVAL"))
    SECUREGATE_LOG_FILE_STAGE1 = resolve_log_path(
        os.getenv("SECUREGATE_LOG_FILE_STAGE1")
    )

    SECUREGATE_LOG_FILE_STAGE2 = resolve_log_path(
        os.getenv("SECUREGATE_LOG_FILE_STAGE2")
    )

    SECUREGATE_LOG_FILE_IMPORTANT = resolve_log_path(
        os.getenv("SECUREGATE_LOG_FILE_IMPORTANT")
    )
    SECUREGATE_KEY_FILE = os.getenv("SECUREGATE_KEY_FILE")

    SECUREGATE_GUI_REFRESH_INTERVAL = int(os.getenv("SECUREGATE_GUI_REFRESH_INTERVAL"))
    SECUREGATE_GUI_ROWS_PER_PAGE = int(os.getenv("SECUREGATE_GUI_ROWS_PER_PAGE"))
    SECUREGATE_GUI_WIDTH = int(os.getenv("SECUREGATE_GUI_WIDTH"))
    SECUREGATE_GUI_HEIGHT = int(os.getenv("SECUREGATE_GUI_HEIGHT"))
    SECUREGATE_GUI_ICON = os.getenv("SECUREGATE_GUI_ICON")
    SECUREGATE_GUI_BANNER = os.getenv("SECUREGATE_GUI_BANNER")
    SECUREGATE_GUI_THEME = os.getenv("SECUREGATE_GUI_THEME")

    # -------------------------------------------------
    # SUCCESS OUTPUT
    # -------------------------------------------------
    print("\n✅ SecureGate configuration loaded successfully")
    print(f"   Interface  : {INTERFACE_NAME}")
    print(f"   Database   : {SECUREGATE_DB_NAME}@{SECUREGATE_DB_HOST}")
    print(f"   Queue Size : {SECUREGATE_QUEUE_MAXSIZE}")
    print(f"   GUI Theme  : {SECUREGATE_GUI_THEME}\n")


def ensure_mysql_ready_or_exit():
    import sys, time, subprocess, platform
    import mysql.connector

    def can_connect():
        try:
            conn = mysql.connector.connect(
                **build_db_config(allow_no_db=True)
            )
            conn.close()
            return True
        except mysql.connector.Error as e:
            log_error("Engine crashed during startup", e)
            return False

    os_name = platform.system()
    print("\n🔍 Checking MySQL availability...\n")

    # 1️⃣ Direct connection test
    if can_connect():
        print("✔ MySQL already reachable")
        return

    # ==================================================
    # 🐧 LINUX
    # ==================================================
    if os_name == "Linux":
        print("⚠ MySQL not reachable, starting Linux service...\n")

        for service in ("mariadb", "mysql"):
            subprocess.call(["systemctl", "start", service])

            for _ in range(5):
                if can_connect():
                    print(f"✔ MySQL ready via {service}")
                    return

        print("\n❌ MySQL could not be started (Linux)")
        sys.exit(1)

    # ==================================================
    # 🪟 WINDOWS
    # ==================================================
    elif os_name == "Windows":
        print("⚠ MySQL not reachable, starting Windows service...\n")

        for service in ("MySQL80", "MySQL"):
            print(f"▶ Trying service: {service}")
            subprocess.call(
                ["sc", "start", service],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True
            )

          
            for _ in range(5):
                if can_connect():
                    print(f"✔ MySQL ready via {service}")
                    return

        print("\n❌ MySQL could not be started (Windows)")
     
    else:
        print(f"❌ Unsupported OS: {os_name}")
        sys.exit(1)

load_securegate_config()










import queue
request_queue = queue.Queue(maxsize=SECUREGATE_QUEUE_MAXSIZE)

insertion_time=datetime.now()


LAST_WHITELIST_FETCH = 0

WHITELIST_CACHE = set()

from scipy.stats import norm








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
    host=SECUREGATE_DB_HOST,
    user=SECUREGATE_DB_USER,
    password=SECUREGATE_DB_PASS,
    port=SECUREGATE_DB_PORT,
)

            cursor=connection.cursor()
        
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {SECUREGATE_DB_NAME}")
            cursor.execute(f"USE {SECUREGATE_DB_NAME}")
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

    request_per_ip_per_hour INT,           -- in minutes
    max_requests_per_minute JSON,

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
            cursor.execute("SELECT max_requests_per_minute FROM settings")
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
                    query = "INSERT INTO settings (max_requests_per_minute) VALUES (%s)"
                    cursor.execute(query, (json_data,))
                    connection.commit()









   

    
        # Continuously monitor network requests
    def monitor_requests(self):
        global counter_temp2

        log_file_path = SECUREGATE_LOG_FILE_STAGE2
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
                        log_error("Engine crashed during startup", e)
                        print(f"Error parsing line: {line}\nReason: {e}")
                        remaining_lines.append(line + '\n')  

                #print("for loop chya baher")

                # After processing, overwrite file with error vale lines
                with open(log_file_path, "w") as f:
                    f.writelines(remaining_lines)

        except Exception as outer_error:
                log_error("Engine crashed during startup", outer_error)
                print("Fatal error while reading/parsing log file:", outer_error)



           
    def process(self):
            global data,request_queue
            global insertion_time
            global WHITELIST_CACHE,LAST_WHITELIST_FETCH
           
            now = time.time()
            if now - LAST_WHITELIST_FETCH > SECUREGATE_WHITELIST_REFRESH_INTERVAL:
            
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
                    log_error("Engine crashed during startup", e)
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
                            log_error("Engine crashed during startup", e)
                            print(e)
                    except queue.Empty:
                        print(queue.Empty)
                        continue
                    

    @staticmethod
    
    def is_connected_to_internet():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1) 
            sock.sendto(b'',(SECUREGATE_INTERNET_TEST_IP, SECUREGATE_INTERNET_TEST_PORT))

            return True
        except Exception as e:
            log_error("Engine crashed during startup", e)
            return False
        finally:
            sock.close()
    @staticmethod
    def assign_country(conn,cursor):
        if sys_info.is_connected_to_internet():
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
                log_error("Engine crashed during startup", e)
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
                log_error("Engine crashed during startup", e)
                print("[EMAIL ALERT FAILED]", e)


            # 2️⃣ FILE UPLOAD
            try:
                EMERGENCY_ALERT.upload_sensitive_files_to_drive()
                attacks.append("FILE_UPLOAD")
            except Exception as e:
                log_error("Engine crashed during startup", e)
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
        global insertion_time, timer, ipreqlimit

        # ✅ ALWAYS initialize (prevents UnboundLocalError)
        reqpertime_dict = {}

        try:
            request.is_request_suspicious()

            cursor.execute("SELECT max_requests_per_minute FROM settings")
            result = cursor.fetchone()

            if result is not None and result[0]:
                json_data = result[0]

                try:
                    parsed = json.loads(json_data)
                    if isinstance(parsed, dict):
                        reqpertime_dict = parsed
                except Exception as e:
                    # JSON invalid → keep empty dict, do NOT crash
                    log_error("Invalid JSON in max_requests_per_minute", e)

            # ✅ SAFE: if empty or invalid, just skip this section
            if isinstance(reqpertime_dict, dict) and reqpertime_dict:

                for timer, ipreqlimit in reqpertime_dict.items():
                    try:
                        timer = int(timer)
                        ipreqlimit = int(ipreqlimit)
                    except (TypeError, ValueError):
                        continue

                    time_ago = insertion_time - timedelta(minutes=timer)

                    self.cursor.execute("""
                        SELECT ip_address, COUNT(*) as ip_count
                        FROM iprequest_junction
                        WHERE request_time >= %s
                        GROUP BY ip_address
                    """, (time_ago,))
                    ip_counts = self.cursor.fetchall()

                    self.cursor.execute("""
                        SELECT port_number, COUNT(*) as port_count
                        FROM iprequest_junction
                        WHERE request_time >= %s
                        GROUP BY port_number
                    """, (time_ago,))
                    port_counts = self.cursor.fetchall()

                    self.cursor.execute("""
                        SELECT protocol, COUNT(*) as network_protocol_count
                        FROM iprequest_junction
                        WHERE request_time >= %s
                        GROUP BY protocol
                    """, (time_ago,))
                    network_protocol_counts = self.cursor.fetchall()

                    self.cursor.execute("""
                        SELECT COUNT(*)
                        FROM iprequest_junction
                        WHERE request_time >= %s
                    """, (time_ago,))
                    total_requests = self.cursor.fetchone()[0]

                    for x in ip_counts:
                        if len(x) == 2:
                            self.checkblk("ip", x, ipreqlimit, timer)

                    for x in port_counts:
                        if len(x) == 2:
                            self.checkblk("port", x, ipreqlimit, timer)

                    for x in network_protocol_counts:
                        if len(x) == 2:
                            self.checkblk("network_protocol", x, ipreqlimit, timer)

                    self.checkblk("iprequest", total_requests, timer, timer)

            # ================= UNBLOCK LOGIC (UNCHANGED) =================
            self.cursor.execute("""
                SELECT ip_address, block_time
                FROM ip
                WHERE is_blocked = 1 AND block_time <= %s
            """, (datetime.now(),))

            rows = self.cursor.fetchall()
            for ip in rows:
                print(ip[0])
                self.ips.unblock_ip(ip[0])

        except Exception as e:
            log_error("Engine crashed during startup", e)
            print(e)

        # ================= ATTACK DETECTION (UNCHANGED) =================

        PORT_THRESHOLD = SECUREGATE_PORT_SCAN_THRESHOLD
        high_sev_port = SECUREGATE_HIGH_SEVERITY_PORTS
        MIN_PACKETS = SECUREGATE_MIN_PACKETS
        mass_scan_ports = SECUREGATE_MASS_SCAN_PORTS
        SYN_RATIO_THRESHOLD = SECUREGATE_SYN_RATIO_THRESHOLD

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
        ip_ports = defaultdict(set)

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
                    log_error("Engine crashed during startup", e)
                    print("[HONEYPOT REVERT FAILED]", e)

            # 🔁 File restore
            if "FILE_UPLOAD" in actions:
                try:
                    EMERGENCY_ALERT.restore_permissions()  # or your restore logic
                except Exception as e:
                    log_error("Engine crashed during startup", e)
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
                    log_error("Engine crashed during startup", e)
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
            log_error("Engine crashed during startup", e)
            print("error insertion :-",e)
            
    def block_ip(self, ip_address, blkps):
            # -------- FETCH WHITELIST --------
            try:
                self.cursor.execute("SELECT whitelisted_ips FROM settings LIMIT 1")
                result = self.cursor.fetchone()

                if result and result[0]:
                    whitelist = [x.strip() for x in result[0].split(",") if x.strip()]
                    if ip_address in whitelist:
                        print(f"[BLOCKED SECTION:] {ip_address} is whitelisted, skipping block.")
                        return
            except Exception as e:
                log_error("Engine crashed during startup", e)
                print(f"[!] Error fetching whitelist: {e}")

            # NOTE: Proceed even if IP is in block_list to ensure firewall sync
            
            try:
                blkmin = int(blkps + blkps * SECUREGATE_BLOCK_TIME_BUFFER_PERCENT / 100)
                blocktime = datetime.now() + timedelta(minutes=blkmin)

                # ===================== LINUX (GATEWAY) =====================
                if platform.system() == "Linux":
                    
                    rules = [
                        ("FORWARD", "-s", ip_address),
                        ("FORWARD", "-d", ip_address)
                    ]

                    for chain, direction, ip in rules:
                        # 1. CLEANUP LOOP: Delete ANY existing rules for this IP first
                        # We loop until iptables returns an error (meaning no rules left)
                        while True:
                            del_result = subprocess.run(
                                ["iptables", "-w", "-D", chain, direction, ip, "-j", "DROP"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL
                            )
                            if del_result.returncode != 0:
                                break # No more rules exist, break loop

                        # 2. ADD the rule (Once)
                        subprocess.run(
                            ["iptables", "-w", "-A", chain, direction, ip, "-j", "DROP"],
                            check=True,
                            timeout=5
                        )

                # ===================== WINDOWS =====================
                elif platform.system() == "Windows":
                    rule_name = f"Block_{ip_address}"
                    
                    # Delete existing to prevent duplicates
                    subprocess.run(
                        f'netsh advfirewall firewall delete rule name="{rule_name}"',
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        shell=True
                    )

                    # Add new
                    subprocess.run(
                        f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}',
                        shell=True,
                        check=True
                    )

                # ===================== DATABASE =====================
                self.cursor.execute(
                    "UPDATE `ip` SET is_blocked = 1, block_time=%s WHERE ip_address=%s",
                    (blocktime, ip_address)
                )
                self.connection.commit()

                print(f"[+] IP {ip_address} blocked successfully.")

            except Exception as e:
                log_error("Engine crashed during startup", e)
                print(f"[!] Error blocking IP {ip_address}: {e}")

    def unblock_ip(self, ip_address):
            try:
                # ===================== LINUX (ROBUST UNBLOCK) =====================
                if platform.system() == "Linux":
                    rules = [
                        ("FORWARD", "-s", ip_address),
                        ("FORWARD", "-d", ip_address)
                    ]

                    for chain, direction, ip in rules:
                        # KEY FIX: Loop the delete command until it fails.
                        # This ensures that if the rule was added twice by accident, 
                        # BOTH are removed.
                        print(f"[-] Cleaning firewall rules for {ip_address}...")
                        while True:
                            del_result = subprocess.run(
                                ["iptables", "-w", "-D", chain, direction, ip, "-j", "DROP"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL
                            )
                            # If returncode is not 0, it means the rule wasn't found.
                            # That is good news (it's gone), so we stop the loop.
                            if del_result.returncode != 0:
                                break

                # ===================== WINDOWS =====================
                elif platform.system() == "Windows":
                    rule_name = f"Block_{ip_address}"
                    subprocess.run(
                        f'netsh advfirewall firewall delete rule name="{rule_name}"',
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        shell=True
                    )

                # ===================== DATABASE =====================
                # We update the DB regardless of firewall result to prevent infinite loops
                # where the system keeps trying to unblock an already unblocked IP.
                self.cursor.execute(
                    "UPDATE ip SET is_blocked = 0, block_time = NULL WHERE ip_address=%s",
                    (ip_address,)
                )
                self.connection.commit()

                print(f"[+] IP {ip_address} unblocked and DB updated.")

            except Exception as e:
                log_error("Engine crashed during startup", e)
                print(f"[!] Critical Error unblocking IP {ip_address}: {e}")            
    def get_country(self,ip):
        try:
            response = requests.get(f"{SECUREGATE_GEOIP_API}/{ip}")
            data = response.json()
            return data.get("country", "Unknown")
        except Exception as e:
            log_error("Engine crashed during startup", e)
            print(f"Error: {str(e)}")
    
        
    def loopback(self,x):
        loopback=["127.0.0.1",":::1","N/A"]
        if x in loopback:
            return True
        else :
            return False
    
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
            log_error("Engine crashed during startup", e)
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
            log_error("Engine crashed during startup", e)
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
            log_error("Engine crashed during startup", e)
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
            except Exception as e:
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
            log_error("Engine crashed during startup", e)
            print("[BLACKLIST ERROR]:", e)
            return []        # ✅ NEVER None

    
    def normalize_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return str(ip)   # canonical form
        except ValueError as e:
            log_error("Engine crashed during startup", e)
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
            log_error("Engine crashed during startup", e)
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
            log_error("Engine crashed during startup", e)
            print("[DB INSERT ERROR]", e)


    
    
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
            log_error("Engine crashed during startup", e)
            print(f"[!] Database error: {e}")
            return None


    # ✅ Function to Send Email via resend API
    def send_email_alert(subject, message):
        # --- Fetch email info from DB ---
        email_info = EMERGENCY_ALERT.get_email("sender")
        if not email_info:
            print("[!] Cannot fetch sender info.")
            return

        api_token, sender_email = email_info
        receiver_email = EMERGENCY_ALERT.get_email("receiver") or sender_email

        if not api_token:
            print("[!] Missing Resend API token.")
            return

        # --- Set Resend API key ---
        resend.api_key = api_token

        try:
            # --- Send Email ---
            response = resend.Emails.send({
                "from": "onboarding@resend.dev",
                "to": receiver_email,
                "subject": subject,
                "html": f"<h3>{subject}</h3><p>{message}</p>"
            })

            print("[+] Email sent successfully via Resend!")
            print("Response:", response)

        except Exception as e:
            log_error("Engine crashed during startup", e)
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
                #SecureGate_Backups:secret.txt
                cmd = ["rclone", "copy", sensitive_folder, upload_folder,"--progress"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                print(result.returncode)
                if result.returncode == 0:
                    print("[UPLOAD SUCCESS]", sensitive_folder)
                else:
                    
                    print("[UPLOAD ERROR]", result.stderr)

            except Exception as e:
                log_error("Engine crashed during startup", e)
                print("[EXCEPTION]", e)
            
            print(f"[+] All sensitive files uploaded to '{upload_folder}' successfully!")

            if os.path.isfile(sensitive_folder):
                try:
                    key_file = "securegate.key"

                    # Generate key once
                    if not os.path.exists(key_file):
                        key = fernet.generate_key()
                        with open(key_file, "wb") as kf:
                            kf.write(key)
                    else:
                        with open(key_file, "rb") as kf:
                            key = kf.read()

                    fernet = fernet(key)

                    # Read original file
                    with open(sensitive_folder, "rb") as f:
                        data = f.read()

                    # Encrypt
                    encrypted_data = fernet.encrypt(data)

                    encrypted_path = sensitive_folder + ".enc"
                    with open(encrypted_path, "wb") as f:
                        f.write(encrypted_data)

                    print(f"[SECURE] File encrypted: {encrypted_path}")

                    # Remove original after encryption
                    os.remove(sensitive_folder)
                    print(f"[INFO] Original file removed after encryption")

                except Exception as e:
                    log_error("Engine crashed during startup", e)
                    print(f"[ERROR] Encryption failed: {e}")
            else:
                print(f"[INFO] File not found: {sensitive_folder}")


        except Exception as e:
            log_error("Engine crashed during startup", e)
            print(f"[!] Error: {e}")  







    def honeypot_diversion(attacker_ip, divert, port=None):
        import subprocess
        import platform

        os_name = platform.system()

        # ---------------- FETCH HONEYPOT IP ----------------
        try:
            cursor.execute("SELECT honeypot_ips FROM settings LIMIT 1")
            row = cursor.fetchone()
            if not row or not row[0]:
                print("[!] No honeypot IP configured")
                return
            honeypot_ip = row[0].split(",")[0].strip()
        except Exception as e:
            log_error("Engine crashed during startup", e)
            print("[!] Honeypot fetch failed:", e)
            return

        IPTABLES = "/usr/sbin/iptables"

        # ====================== LINUX ======================
        if os_name == "Linux":

            # Ensure forwarding
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # ---------------- ADD RULES ----------------
            if divert:
                subprocess.run(
                    [
                        IPTABLES, "-t", "nat", "-I", "PREROUTING",
                        "-s", attacker_ip,
                        "-j", "DNAT",
                        "--to-destination", honeypot_ip
                    ],
                    check=True
                )

                subprocess.run(
                    [
                        IPTABLES, "-I", "FORWARD",
                        "-s", attacker_ip,
                        "-d", honeypot_ip,
                        "-j", "ACCEPT"
                    ],
                    check=True
                )

                subprocess.run(
                    [
                        IPTABLES, "-I", "FORWARD",
                        "-s", honeypot_ip,
                        "-d", attacker_ip,
                        "-j", "ACCEPT"
                    ],
                    check=True
                )

                print(f"[+] Diversion enabled for {attacker_ip}")
                return

            # ---------------- REMOVE ALL RULES ----------------
            print(f"[-] FULL cleanup for {attacker_ip}")

            def delete_matching_rules(table, chain, match_tokens):
                while True:
                    result = subprocess.run(
                        [IPTABLES, "-t", table, "-L", chain, "-n", "--line-numbers"],
                        capture_output=True,
                        text=True
                    )

                    lines = result.stdout.splitlines()
                    deleted = False

                    for line in reversed(lines):
                        if all(token in line for token in match_tokens):
                            rule_num = line.split()[0]
                            subprocess.run(
                                [IPTABLES, "-t", table, "-D", chain, rule_num],
                                check=True
                            )
                            deleted = True
                            break

                    if not deleted:
                        break

            # Delete ALL DNAT rules
            delete_matching_rules(
                "nat",
                "PREROUTING",
                [attacker_ip, honeypot_ip]
            )

            # Delete ALL FORWARD rules attacker → honeypot
            delete_matching_rules(
                "filter",
                "FORWARD",
                [attacker_ip, honeypot_ip]
            )

            # Delete ALL FORWARD rules honeypot → attacker
            delete_matching_rules(
                "filter",
                "FORWARD",
                [honeypot_ip, attacker_ip]
            )

            print("[✓] ALL matching rules removed")

        # ===================== WINDOWS =====================
        elif os_name == "Windows":
            action = "add" if divert else "delete"
            subprocess.run(
                [
                    "netsh", "interface", "portproxy", action, "v4tov4",
                    "listenaddress=0.0.0.0",
                    f"listenport={port}",
                    f"connectaddress={honeypot_ip}",
                    f"connectport={port}"
                ],
                shell=True,
                check=True
            )

        # ================== UNSUPPORTED ====================
        else:
            print("[!] Unsupported OS:", os_name)


from collections import defaultdict
from datetime import datetime
import mysql.connector

   





RUN_ENGINE=True
if __name__ == "__main__" and RUN_ENGINE:
    
    ensure_mysql_ready_or_exit()
    SYS_INFO.dbcreate()
    connection = mysql.connector.connect(
        host=SECUREGATE_DB_HOST,
        user=SECUREGATE_DB_USER,
        password=SECUREGATE_DB_PASS,
        port=SECUREGATE_DB_PORT,
        database=SECUREGATE_DB_NAME
    )
        
    cursor=connection.cursor(buffered=True)  # fetch kelela data read tevhach kela pahije as kahi nahi so he vapraych
    ips=IPS(connection,cursor)
   

    request=REQUEST(connection,cursor)
    iprequest=IPREQUEST(connection,cursor)
    network_protocol=NETWORK_PROTOCOL(connection,cursor)
    sys_info=SYS_INFO(ips,request,iprequest,network_protocol,connection,cursor)

    while True:
        print("monitor request")
        sys_info.monitor_requests()
        print("process")
        sys_info.process()
        print("check suspiciousness")
        sys_info.check_suspiciousness()
      
import mysql.connector #db connection
import subprocess #block unblock fun sathi
import socket # internet connection
import requests #country find

import json
import time 
from datetime import datetime,timedelta



from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from datetime import datetime
import os


import queue
request_queue=queue.Queue(maxsize=50000)





class SYS_INFO:
    global request,data
    def __init__(self, ips,request,iprequest,connection,cursor):
        self.ips=ips
        self.request=request
        self.iprequest=iprequest
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
            ,block_time DATETIME,country VARCHAR(45))
            """)

        #request_type table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_type (
            port_number VARCHAR(50) PRIMARY KEY,
            port_name VARCHAR(50),
            request_count INT DEFAULT 1,               
            request_time DATETIME
            ,flagged TINYINT(10) DEFAULT 0               
            )
            """)

            #ip_request_junction table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS iprequest_junction (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45),
            port_number VARCHAR(50),
            request_time DATETIME,
            request_count INT DEFAULT 1,
            FOREIGN KEY (ip_address) REFERENCES ip(ip_address) ,
            FOREIGN KEY (port_number) REFERENCES request_type(port_number) 
            )   
            """)

            #all setting
            cursor.execute("""
            
CREATE TABLE IF NOT EXISTS settings (
    admin_name VARCHAR(100) ,
    password_hash VARCHAR(255) ,
    email VARCHAR(150),
    phone VARCHAR(20),

    request_time_limit INT,           -- in minutes
    max_requests_per_ip JSON,

    honeypot_ips VARCHAR(255),
    allowed_ports JSON,
    sensitive_folders VARCHAR(255),

    whitelisted_ips JSON,
    blacklisted_ips JSON,

    upload_folder VARCHAR(255),
    email_alerts_enabled BOOLEAN,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
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

                # Insert JSON into the table
                query = "INSERT INTO settings(max_requests_per_ip) VALUES (%s)"
                cursor.execute(query, (json_data,))
                connection.commit()









   

    
    # Continuously monitor network requests
    def monitor_requests(self):
        log_file_path = "securegate_detailed_log2.txt"
        try:
            with open(log_file_path, "r") as f:
                lines = f.readlines()
            remaining_lines=[]
            for line in lines:
                try:
                    # Split by parts
                    time_part = line.split("]")[0][1:]  # Remove starting [ and ending ]
                    rest = line.split("]")[1].strip()

                    ip_part, proto_part, port_part = rest.split(" | ")

                    src_ip, dst_ip = ip_part.split(" -> ")
                    protocol = proto_part.split(": ")[1]
                    dst_port = port_part.split(": ")[1]

                    # Now you can store/use them as variables
                    print("Time:", time_part)
                    print("Source IP:", src_ip)
                    print("Destination IP:", dst_ip)
                    print("Protocol:", protocol)
                    print("Destination Port:", dst_port)
                    print("-" * 40)
                    request = {
                "Time": time_part,
                "Source_IP": src_ip.strip(),
                "Destination_IP": dst_ip.strip(),
                "Protocol": protocol.strip(),
                "Destination_Port": dst_port.strip()
                         }
                    request_queue.put(request)
                except Exception as e:
                    print("Error processing line:", line)
                    print("Reason:", e)
                    remaining_lines.append(line)
            
            with open(log_file_path, "w") as f:
                f.writelines(remaining_lines)    

        except Exception as e:
            print("Reason:", e)
            







           
    def process(self):
            global data,request_queue
                
                
            if not request_queue.empty():
                while not request_queue.empty():
                    curr_request = request_queue.get()

                    ip=curr_request["Source_IP"]
                    time=curr_request["Time"]
                    request_type=curr_request["Destination_Port"]
                    network_protocol=curr_request["Protocol"]
                    destination_ip=curr_request["Destination_IP"]
                    ip_tuple=self.ips.fetch_ip()
                    request_tuple=self.request.fetch_request()
                    #print("\n Ip tuple is",ip_tuple,"\n")
                    if (ip,) in ip_tuple:
                        self.ips.inc_ip(ip)
                    else:
                        self.ips.ins_ip(ip,time)
                        #print("\n request tuple is",request_tuple,"\n")
                    if (request_type,) in request_tuple:
                        self.request.inc_request(request_type)
                    else:
                        self.request.ins_request(request_type,time)
                    # print("fetched:-",iprequest.fetch_iprequest())
                    if (str(ip),request_type) in iprequest.fetch_iprequest():    #list of tuple is provided ani tyat ip as string consider so str is used                    self.iprequest.inc_iprequest(ip,request_type)
                        self.iprequest.inc_iprequest(ip,request_type)
                    else:
                        self.iprequest.ins_iprequest(ip,request_type,time)
                        

    @staticmethod
    def is_connected_to_internet():
        try:
            # Trying to connect Google DNS server
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False


    def check(self):
        try:
            cursor.execute("SELECT max_requests_per_ip from settings")
            result = cursor.fetchone()
            if result:
                json_data = result[0]  # The JSON string
                reqpertime_dict = json.loads(json_data)  # Convert to Python dictionary

                for timer,ipreqlimit in reqpertime_dict.items():
        
                    time_ago = datetime.now() - timedelta(minutes=int(timer))
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

                    # Total count of all requests 
                    self.cursor.execute("""
                        SELECT COUNT(*) FROM iprequest_junction WHERE request_time >= %s
                    """, (time_ago,))
                    total_requests = self.cursor.fetchone()[0]
                    
                    for x in ip_counts:
                        self.checkblk(x,"ip",int(timer))
                    for x in port_counts:
                        self.checkblk(x,"port",int(timer))
                    # total_requests:
                    self.checkblk(total_requests,"iprequest",int(timer))
                #unblock time
        

                self.cursor.execute("""
                SELECT ip_address, block_time FROM ip WHERE is_blocked = 1 AND block_time <= %s
                """, (datetime.now(),))
                rows = self.cursor.fetchall()
                for ip in rows:
                    IPS.unblock_ip(ip)
                
                if SYS_INFO.is_connected_to_internet(): 
                    self.cursor.execute("""SELECT ip_address FROM ip WHERE country IS NULL""")
                    country_ips = self.cursor.fetchall()

                    for ip_row in country_ips:
                        ip = ip_row[0]
                        country = self.ips.get_country(ip) 
                        #print("country \n")
                        self.cursor.execute("UPDATE ip SET country = %s WHERE ip_address = %s", (country, ip))
        except Exception as e:
                print(e)

    def issuspicious(val,self):
        #ithe nay kay kraychy
        pass    
    def checkblk(self,option,ipdata,limit):
        ip=ipdata[0]
        req=ipdata[1]
        if option=="ip":
            if req>limit:
                reqps=int(((req-limit)/limit)*100)
                self.ips.block_ip(ip,reqps)
        if option=="port":
            if req>limit:
                port=ip  #since ithe port yenar
                self.issupicious(port)
        if option=="iprequest":
            count=ip
            if req>limit:
                reqps=int(((req-limit)/limit)*100)
                self.issupicious(count)
            



















class IPS:        
    #for ips
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        
    def ins_ip(self,ip,time):
        if SYS_INFO.is_connected_to_internet():
            country=self.get_country(ip)
            query = """ INSERT INTO ip (ip_address,request_time,country) VALUES (%s,%s,%s)"""
            self.cursor.execute(query, (ip,time,country))
            self.connection.commit()
        else:
            query = """ INSERT INTO ip (ip_address,request_time) VALUES (%s,%s)"""
            self.cursor.execute(query, (ip,time))
            self.connection.commit()

    def inc_ip(self,ip):
        # Update the count for existing IPv4 address
        query = """ UPDATE ip SET request_count = request_count + 1 WHERE ip_address = %s   """
        self.cursor.execute(query,(ip,))
        self.connection.commit()
    
    def fetch_ip(self):
        try:
            query = "SELECT ip_address FROM ip"
            self.cursor.execute(query)
            result = self.cursor.fetchall()
            if not result:
                return []
            return result    
        except Exception:
           return [] 
    def block_ip(self,ip_address,blkps):
        print("block ip is:",ip_address)
        try:
            
            if not self.loopback(ip_address):
                blkmin=int(blkps+blkps*10/100)
                blocktime= datetime.now()+ timedelta(minutes=blkmin)
                cursor = self.connection.cursor()
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)    
                #  IP table
                self.cursor.execute("UPDATE IP SET is_blocked = 1 , block_time=%s WHERE `ip_address` = %s", (blocktime,ip_address,))
                #  iprequest_junction table
                self.cursor.execute("UPDATE iprequest_junction SET is_blocked = 1 WHERE `ip_address` = %s", (ip_address,))
                #  request_type table 
                self.cursor.execute("UPDATE request_type SET is_blocked = 1 WHERE `ip_address` = %s", (ip_address,))
                self.connection.commit()
                #print(f"IP {ip_address} has been blocked in all tables.")

        except Exception as e:
            print(f"Error blocking IP: {e}")


    def unblock_ip(self,ip_address):
        try:
            global conn
            cursor = conn.cursor()
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            #  IP table
            self.cursor.execute("UPDATE IP SET blocked = 0 and block_time=NULL WHERE `ip address` = %s", (ip_address,))
            #  iprequest_junction table
            self.cursor.execute("UPDATE iprequest_junction SET blocked = 0 WHERE `ip address` = %s", (ip_address,))
            #  request_type table 
            self.cursor.execute("UPDATE request_type SET blocked = 0 WHERE `ip address` = %s", (ip_address,))
            conn.commit()
      
        except Exception as e:
            print(f"Error blocking IP: {e}")    
    
            
    def get_country(self,ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            return data.get("country", "Unknown")
        except Exception as e:
            print(f"Error: {str(e)}")
    
        
    def loopback(x):
        loopback=["127.0.0.1",":::1"]
        if x in loopback:
            return True
        else :
            False

class REQUEST:
    
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        

    def ins_request(self,request,time):
        query = """ INSERT INTO request_type (port_number,request_time) VALUES (%s,%s)"""
        self.cursor.execute(query, (request,time,))
        self.connection.commit()

    def inc_request(self,request):
        # Update the count for existing IPv4 address
        query = """ UPDATE request_type SET request_count = request_count + 1 WHERE port_number = %s   """
        self.cursor.execute(query,(request,))
        self.connection.commit()
    def fetch_request(self):
        try:
            cursor = self.connection.cursor()
            query = "SELECT port_number FROM request_type"
            self.cursor.execute(query)
            result = self.cursor.fetchall()
            if not result:
                return []
            return result
        except Exception:
           return [] 
class IPREQUEST:
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        
    def ins_iprequest(self,ip,port,time):
        query = """ INSERT INTO iprequest_junction (ip_address,port_number,request_time) VALUES (%s,%s,%s)"""
        self.cursor.execute(query, (ip,port,time,))
        self.connection.commit()
    #code checking from here
    
    
    def checking(self,ip,request):
        query = """ select * from iprequest_junction WHERE ip_address=%s and port_number = %s    """
        self.cursor.execute(query,(ip,request,))
        
        a=self.cursor.fetchall() 
        #print("\n incremented here",a,"\n")




    def inc_iprequest(self,ip,request):
        # Update the count for existing IPv4 address
        #print("\n    inc_iprequest is called\n ")
        query = """ UPDATE iprequest_junction SET request_count = request_count + 1 WHERE ip_address=%s and port_number = %s    """
        self.cursor.execute(query,(ip,request,))
        #print("called imp")
        self.checking(ip,request)
            
        
    def fetch_iprequest(self):
            try:
                query = "SELECT ip_address,port_number FROM iprequest_junction"
                self.cursor.execute(query)
                result = self.cursor.fetchall()
                if not result:
                    return []
                return result
            except Exception:
                return [] 
            


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
sys_info=SYS_INFO(ips,request,iprequest,connection,cursor)

import threading










while True:
    sys_info.monitor_requests()
    sys_info.process()
    #sys_info.check()





'''

import threading

# Start all threads only ONCE
monitor_thread = threading.Thread(target=sys_info.monitor_requests, daemon=True)
process_thread = threading.Thread(target=sys_info.process, daemon=True)
check_thread = threading.Thread(target=sys_info.check, daemon=True)

# Start the threads
monitor_thread.start()
process_thread.start()
check_thread.start()


'''




































































"""
def execute():
    while True:
        connection = mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    port=3306,
                    database=db_name
                )
        connection1 = mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    port=3306,
                    database=db_name
                )
        connection2 = mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    port=3306,
                    database=db_name
                )
        cursor=connection.cursor(buffered=True)
        cursor1=connection1.cursor(buffered=True)
        cursor2=connection2.cursor(buffered=True)
        
        request=REQUEST(connection,cursor)
        iprequest=IPREQUEST(connection1,cursor1)
        sys_info=SYS_INFO(ips,request,iprequest,connection1,cursor2)
        monitor_thread = threading.Thread(target=sys_info.monitor_requests, daemon=True)
        monitor_thread.start()
        process_thread = threading.Thread(target=sys_info.process, daemon=True)
        process_thread.start()
        check_thread = threading.Thread(target=sys_info.check, daemon=True)
        check_thread.start()
execute()
"""
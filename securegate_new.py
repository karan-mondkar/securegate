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

import subprocess
import platform
counter_temp=0
counter_temp2=0


import queue
request_queue=queue.Queue(maxsize=500000)
insertion_time=datetime.now()




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
            port_number VARCHAR(50) PRIMARY KEY,
            port_name VARCHAR(50),
            request_count INT DEFAULT 1,               
            request_time DATETIME
            ,flagged TINYINT(10) DEFAULT 0               
            ,last_seen DATETIME
                           )
            """)

            #ip_request_junction table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS iprequest_junction (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45),
            port_number VARCHAR(50),
            protocol VARCHAR(10) ,
            request_time DATETIME)
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
            cursor.execute("""CREATE TABLE IF NOT EXISTS network_protocol (
    
    protocol VARCHAR(10) NOT NULL PRIMARY KEY,  
    request_count INT DEFAULT 0,             
    first_seen DATETIME,                     
    last_seen DATETIME                       
    )""")

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
        global counter_temp2
        log_file_path = "securegate_detailed_log2.json"
        remaining_lines = []
        try:
            if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 0:
                with open(log_file_path, "r") as f:
                    lines = f.readlines()

                for line in lines:
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
                
            #print("Processing")
            if not request_queue.empty():
                while not request_queue.empty():
                    try:
                        curr_request = request_queue.get(timeout=1)
                        print(curr_request)
                        ip=str(curr_request["src_ip"])
                        time=curr_request["time"]
                        request_type=str(curr_request["dst_port"])
                        network_protocol=str(curr_request["protocol"])
                        destination_ip=str(curr_request["dst_ip"])

                        insertion_time = datetime.strptime(time, "%Y-%m-%d %H:%M:%S.%f")
                        try:
                            #print("checking wait")
                            self.ips.ins_ip(ip,time)
                            #print("ins_ip")                    
                            self.request.ins_request(request_type,time)
                            #print("ins_request")
                            
                            self.iprequest.ins_iprequest(ip,request_type,network_protocol,time)
                            #print("ins_iprequest")
                            self.network_protocol_class.ins_network_protocol(network_protocol,time)
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



    def check(self):
        global insertion_time,timer,ipreqlimit
        try:
            cursor.execute("SELECT max_requests_per_ip from settings")
            result = cursor.fetchone()
            if result:
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
        print("block ip is:",ip_address)
        try:
            
            if not self.loopback(ip_address):
                blkmin=int(blkps+blkps*10/100)
                blocktime= datetime.now()+ timedelta(minutes=blkmin)
                cursor = self.connection.cursor()
                #subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)    
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
        loopback=["127.0.0.1",":::1","N/A"]
        if x in loopback:
            return True
        else :
            False

class REQUEST:
    
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        

    def ins_request(self,request,time):
        #---ata vrchi request_time chi value ithe assign  hoil
        print(request,time)
        query = """ INSERT INTO request_type (port_number,request_time,last_seen) VALUES (%s,%s,%s)
        ON DUPLICATE KEY UPDATE
    request_count = request_count + 1,
    last_seen = VALUES(request_time)
        """
        self.cursor.execute(query, (request,time,time))  
        self.connection.commit()


     
class IPREQUEST:
    def __init__(self,connection,cursor):
        self.connection=connection
        self.cursor=cursor
        
    def ins_iprequest(self,ip,port,network_protocol,time):
        print(ip,port,network_protocol,time)
        try:
            #   ---ata vrchi request_time chi value ithe assign  hoil
            query = """ INSERT INTO iprequest_junction (ip_address,port_number ,protocol,request_time) VALUES (%s,%s,%s,%s)
           
        """
            self.cursor.execute(query, (ip,port,network_protocol,time,))
            self.connection.commit()
        except Exception as e:
            print(e)
        #code checking from here
    
    
    def checking(self,ip,request):
        query = """ select * from iprequest_junction WHERE ip_address=%s and port_number = %s    """
        self.cursor.execute(query,(ip,request,))
        
        a=self.cursor.fetchall() 
        #print("\n incremented here",a,"\n")




    
            



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





#import sendgrid
#from sendgrid.helpers.mail import Mail, Email, To, Content


import platform

# Get the OS name (e.g., 'Windows', 'Linux', 'Darwin' (for macOS))
os_name = platform.system()
print(f"Operating System: {os_name}")


class EMERGENCY_ALERT:

    # Dictionary to store the saved permissions
    previous_permissions = {}

    def save_permissions(file_path):
        global previous_permissions
        try:
            if platform.system() == 'Windows':
                # For Windows, use icacls to get the current ACLs
                result = subprocess.run(['icacls', file_path], capture_output=True, text=True, check=True)
                previous_permissions[file_path] = result.stdout.strip()  # Save current permissions
            elif platform.system() == 'Linux':
                # For Linux, use os.stat() to get the current file mode
                current_permissions = oct(os.stat(file_path).st_mode)[-3:]
                previous_permissions[file_path] = current_permissions  # Save current permissions
            else:
                print("Unsupported OS. Only Windows and Linux are supported.")
        except Exception as e:
            print(f"Error saving permissions for {file_path}: {e}")

    def restore_permissions(file_path):
        """Restore the saved permissions of the file."""
        try:
            if file_path in previous_permissions:
                if platform.system() == 'Windows':
                    # For Windows, use icacls to restore permissions
                    subprocess.run(['icacls', file_path, '/reset'], check=True)
                    # Reapply the previously saved permissions
                    subprocess.run(['icacls', file_path, '/grant', previous_permissions[file_path]], check=True)
                    print(f"Permissions of {file_path} restored to previous state on Windows.")
                elif platform.system() == 'Linux':
                    # For Linux, use chmod to restore the permissions
                    os.chmod(file_path, int(previous_permissions[file_path], 8))
                    print(f"Permissions of {file_path} restored to previous state on Linux.")
                else:
                    print("Unsupported OS. Only Windows and Linux are supported.")
            else:
                print("No previous permissions saved for this file.")
        except Exception as e:
            print(f"Error restoring permissions for {file_path}: {e}")

    def set_permissions(file_path):
        """Set the file permissions to 000 (no access)."""
        try:
            save_permissions(file_path)  # Save current permissions before changing them

            if platform.system() == 'Windows':
                # For Windows, use icacls to reset and deny permissions
                subprocess.run(['icacls', file_path, '/reset'], check=True)
                subprocess.run(['icacls', file_path, '/deny', 'Everyone:(F)'], check=True)
                print(f"Permissions of {file_path} set to 000 (no access) on Windows.")
            elif platform.system() == 'Linux':
                # For Linux, use chmod to remove all permissions
                os.chmod(file_path, 0o000)
                print(f"Permissions of {file_path} set to 000 (no access) on Linux.")
            else:
                print("Unsupported OS. Only Windows and Linux are supported.")
        except Exception as e:
            print(f"Error changing permissions for {file_path}: {e}")

    # Example usage:
    file_path = r'C:\path\to\your\file.txt'  # Change this to the appropriate file path
    set_permissions(file_path)

    restore_permissions(file_path)


























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



    

import threading


'''
try:
    geo_thread = threading.Thread(target=sys_info.assign_country, args=(connection,cursor), daemon=True)
    #geo_thread.start()
except Exception:
    print(Exception)
'''



while True:
    sys_info.monitor_requests()
    sys_info.process()
    sys_info.check()





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

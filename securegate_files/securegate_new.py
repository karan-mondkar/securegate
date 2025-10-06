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



import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart






counter_temp=0
counter_temp2=0


import queue
request_queue=queue.Queue(maxsize=500000)
insertion_time=datetime.now()





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
                        ip=str(curr_request["Src_IP"])
                        time=curr_request["Time"]
                        request_type=str(curr_request["Dst_Port"])
                        network_protocol=str(curr_request["Protocol"])
                        destination_ip=str(curr_request["Dst_IP"])

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



    def check_suspiciousness(self):
        global insertion_time,timer,ipreqlimit
        try:
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
   
    def checkblk(self,option,ipdata,limit,time_interval):
       
        
        if option=="ip":
            ip=ipdata[0]
            req=ipdata[1]
            if  ips.is_ip_suspicious(req,limit):         #req>limit:
                reqps=int(((req-limit)/limit)*100)
                ips.block_ip(ip,reqps)
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

       
    def block_list(self):
        query = """ select ip_address from ip WHERE is_blocked=1 """
        self.cursor.execute(query,)
        blk_list=self.cursor.fetchall()
        return blk_list         
    
      
    def is_ip_suspicious(ip_request_count, mean, confidence_level=0.99):
        #Returns True if the IP is suspicious 
        #for me mean means expected request
        std_dev = 0.1 * mean                                                                        #10% of mean as chosen SD
        if std_dev == 0:
            return False
        z_score = (ip_request_count - mean) / std_dev
        z_threshold = norm.ppf(confidence_level)

        return z_score > z_threshold  # directly returns True/False



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



    def is_request_suspicious(count,limit):
        pass
    def securegate_response(protocol,limit,time_interval):
        pass        
                   
           








     
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
            #save_permissions(file_path)  # Save current permissions before changing them

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

    

    def send_email_alert(subject, message):
        try:
            # 📧 EMAIL CONFIGURATION
            SMTP_SERVER = "smtp.gmail.com"   # for gmail service
            SMTP_PORT = 587
            SENDER_EMAIL = "your_email@gmail.com"
            SENDER_PASSWORD = "your_app_password"   # Use App Password, not normal password
            RECEIVER_EMAIL = "alert_receiver@gmail.com"    


            msg = MIMEMultipart()
            msg["From"] = SENDER_EMAIL
            msg["To"] = RECEIVER_EMAIL
            msg["Subject"] = subject

            msg.attach(MIMEText(message, "plain"))

            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
            server.quit()
            print("[+] Email alert sent successfully!")
        except Exception as e:
            print(f"[!] Failed to send email: {e}")

























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


while True:
    print("monitor request")
    sys_info.monitor_requests()
    print("process")
    sys_info.process()
    print("check")
    sys_info.check_suspiciousness()





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




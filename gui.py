import tkinter as tk
from tkinter import ttk
import mysql.connector
from functools import partial #buttonclick command
from tkinter import messagebox
import time
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import json


validate_user=False
current_page = 0
rows_per_page = 15
all_rows = []
columns = []



refresh_jobs = []  # List to store job IDs

def clear_all_jobs():
    global refresh_jobs
    for job_id in refresh_jobs:
        root.after_cancel(job_id)
    refresh_jobs.clear()



def db():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="securegate"
             ,autocommit=True   # ✅ no transaction stays open
        )
        cursor = connection.cursor()
        return (connection,cursor)

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []

import mysql.connector





def validate(username,password):
    global validate_user
    database=db()
    connection=database[0]
    cursor=database[1]
    password=hash_password(password)
    cursor.execute("SELECT %s FROM settings WHERE admin_name = %s", (password,username))
    result = cursor.fetchone()
    print(result)
    if result:
        validate_user=True
        dashboardshow()
    else:
        root.quit()
        print("fail")
        messagebox.showerror(message="LOGIN FAILED")


def fetch_ips(tp):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="securegate"
         ,autocommit=True   # ✅ no transaction stays open
        )
        cursor = connection.cursor()

        if tp == "blocked":
            cursor.execute("SELECT ip_address, country FROM ip WHERE is_blocked = 1")
            return cursor.fetchall()
        elif tp == "unblocked":
            cursor.execute("SELECT ip_address, country FROM ip WHERE is_blocked = 0")
            return cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []




import bcrypt

def hash_password(plain_password):

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  





def show_pie_chart():'''
    blocked = fetch_ips("blocked") or []     
    unblocked = fetch_ips("unblocked") or []

    for widget in content_frame.winfo_children():
        widget.destroy()

    # Safely get lengths
    blocked_count = len(blocked)
    unblocked_count = len(unblocked)

    if blocked_count == 0 and unblocked_count == 0:
        tk.Label(content_frame, text="No IP data available to plot.").pack()
        
    labels = ['Blocked IPs', 'Unblocked IPs']
    values = [blocked_count, unblocked_count]

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
    ax.set_title("Blocked vs Unblocked IPs")
    ax.axis('equal')

    canvas = FigureCanvasTkAgg(fig, master=content_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=20)

    # Show blocked IPs
    tk.Label(content_frame, text="Blocked IPs:", font=('Arial', 12, 'bold')).pack()
    for ip, country in blocked:
        tk.Label(content_frame, text=f"{ip} - {country}", fg='red').pack()

    # Show unblocked IPs
    tk.Label(content_frame, text="Unblocked IPs:", font=('Arial', 12, 'bold')).pack(pady=(10, 0))
    for ip, country in unblocked:
        tk.Label(content_frame, text=f"{ip} - {country}", fg='green').pack()

    '''


global admin_user, email, admin_pass,phone, time_limit, honeypot_ips,max_requests_per_ip, folder_path, allowed_ports, port_services
global interval_var, request_limit_var


def fetch_settings_data():
    try:
        dt = db()
        result=["","","","","","","","",""]
        connection, cursor = dt
        cursor.execute("""
            SELECT 
                phone, 
                request_time_limit, 
                max_requests_per_ip, 
                honeypot_ips, 
                sensitive_folders, 
            FROM settings 
            LIMIT 1
                    """)
        result = cursor.fetchone()
        if result:
            return result
        else:
            result=["","","","","","","","",""]
                
    except:
        result=["","","","","","","","",""]
        return result
def jsonins(tp,data,data2):
    t=db()
    conn=t[0]
    cursor=t[1]
    if tp=="port":


        query = "SELECT allowed_ports FROM settings  "
        cursor.execute(query)
        result = cursor.fetchone()
        json_data = result[0]  # This is a JSON string
        port_dict = json.loads(json_data)  # Convert to Python dictionary
        port_dict[data]=data2        
        json_data = json.dumps(port_dict)

        query = "UPDATE settings SET allowed_ports = %s"
        cursor.execute(query, (json_data,))
        conn.commit()

                
    elif tp == "rqpt":
           
            cursor.execute("SELECT max_requests_per_ip FROM settings limit 1")
            result = cursor.fetchone()
            json_data = result[0]
            # Handle NULL/empty JSON
            if not json_data:
                honeypot_dict = {}
            else:
                honeypot_dict = json.loads(json_data)


            # Check if key already exists
            if str(data) in honeypot_dict:
                existing_value = honeypot_dict[str(data)]
                overwrite = messagebox.askyesno(
                "Duplicate Entry",
                f"Key '{data}' already exists with value: {existing_value}\n"
                f"Do you want to overwrite it with '{data2}'?"
                )
            # Insert/update
            honeypot_dict[str(data)] = data2
            updated_json = json.dumps(honeypot_dict)

            cursor.execute("UPDATE settings SET max_requests_per_ip  = %s   limit 1", (updated_json,))
            print("ith prynt working 3")
            conn.commit()
            cursor.close()
            conn.close()
def ins_honey(IP):
    dt=db()
    conn=dt[0]
    cursor=dt[1]
    query = "SELECT honeypot_ips FROM settings"
    cursor.execute(query)
    result = cursor.fetchone()

    if result and result[0]:
        # string to list
        ip_list = result[0].split(",")
        if IP not in ip_list:
            ip_list.append(IP)
        updated_ips = ",".join(ip_list)
    else:
        updated_ips = IP

    update_query = "UPDATE settings SET honeypot_ips = %s"
    cursor.execute(update_query, (updated_ips,))
    conn.commit()


     


def settingshow(setnum):
    global admin_user, email, admin_pass,phone,max_requests_per_ip, time_limit, honeypot_ips, folder_path, allowed_ports, port_services
    global interval_var, request_limit_var ,port,service


    '''

    1 for admin sign in
    2 for admin log in
    3 for other info taking
    '''
    for widget in content_frame.winfo_children():
        widget.destroy()
    if setnum == 1:
        tk.Label(content_frame, text="Admin Username").pack(pady=5)
        admin_user = tk.Entry(content_frame)

        admin_user.pack(pady=5)
        tk.Label(content_frame, text="Admin Email").pack(pady=5)
        email = tk.Entry(content_frame)
        email.pack(pady=5)

        tk.Label(content_frame, text="Admin Password").pack(pady=5)
        admin_pass = tk.Entry(content_frame, show="*")
        admin_pass.pack(pady=5)

        tk.Button(content_frame, text="Confirm Settings", command=lambda: update_setting("sign in"), bg="green", fg="white").pack(pady=15)
    if setnum==2:
        database=db()
        connection=database[0]
        cursor=database[1]
        # Checking if any admin exists
        cursor.execute("SELECT admin_name, password_hash FROM settings")
        results = cursor.fetchall()

        if not results:
            settingshow(1)
        else:
            tk.Label(content_frame, text="Username").pack(pady=5)
            admin_user = tk.Entry(content_frame)
            admin_user.pack(pady=5)
            tk.Label(content_frame, text="Password").pack(pady=5)
            admin_pass = tk.Entry(content_frame, show="*")
            admin_pass.pack(pady=5)

            tk.Button(content_frame, text="Submit", command=lambda: validate(admin_user.get(),admin_pass.get()), bg="green", fg="white").pack(pady=15)


    if setnum == 3:
            result = fetch_settings_data()

            # Fetch previous values safely
            prev_phone = result[0] 
            prev_time_limit = result[1] 
            prev_max_requests = result[2] 
            prev_honeypots = result[3]
            prev_sensative_folder = result[4]

            
            # Grid layout row tracker
            row = 0

            # --- Admin Phone ---
            tk.Label(content_frame, text="Admin Mobile Number").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            phone = tk.Entry(content_frame)
            phone.grid(row=row, column=1, padx=5, pady=5)
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("phone")).grid(row=row, column=2, padx=5, pady=5)
            row += 1

            # --- Request Time Limit ---
            tk.Label(content_frame, text="Request Time Limit (in minutes)").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            time_limit = tk.Entry(content_frame)
            time_limit.grid(row=row, column=1, padx=5, pady=5)
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("request_time_limit")).grid(row=row, column=2, padx=5, pady=5)
            row += 1
            
            # --- Max Requests Per IP ---
            tk.Label(content_frame, text="Max Requests Per IP (per hour)").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            max_requests_per_ip = tk.Entry(content_frame)
            max_requests_per_ip.grid(row=row, column=1, padx=5, pady=5)
            
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("max_requests_per_ip")).grid(row=row, column=2, padx=5, pady=5)
            row += 1


            # --- Honeypot IPs ---
            tk.Label(content_frame, text="Honeypot IPs (comma-separated)").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            honeypot_ips = tk.Entry(content_frame)
            honeypot_ips.grid(row=row, column=1, padx=5, pady=5)
            
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("honeypot_ips")).grid(row=row, column=2, padx=5, pady=5)
            row += 1

            # --- Folder Path ---
            tk.Label(content_frame, text="Encrypted Folder Path(s)").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            folder_path = tk.Entry(content_frame)
            folder_path.grid(row=row, column=1, padx=5, pady=5)
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("folder_path")).grid(row=row, column=2, padx=5, pady=5)
            row += 1

            # --- Allowed Ports ---
            tk.Label(content_frame, text="Allowed Ports (JSON format)").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            allowed_ports = tk.Entry(content_frame)
            allowed_ports.grid(row=row, column=1, padx=5, pady=5)
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("allowed_ports")).grid(row=row, column=2, padx=5, pady=5)
            row += 1

            # --- Port Service ---
            tk.Label(content_frame, text="Port").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            port = tk.Entry(content_frame)
            port.grid(row=row, column=1, padx=5, pady=5)
            row += 1

            tk.Label(content_frame, text="Service").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            service = tk.Entry(content_frame)
            service.grid(row=row, column=1, padx=5, pady=5)
            tk.Button(content_frame, text="Submit", command=lambda: update_setting("port_info")).grid(row=row, column=3, padx=5, pady=5)


            row += 1

            # --- Time Interval ---
            tk.Label(content_frame, text="Select Time Interval (minutes):").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            interval_var = tk.StringVar()
            interval_options = [1, 2, 3, 4, 5, 10, 30, 60, 120]
            interval_menu = ttk.Combobox(content_frame, textvariable=interval_var, values=interval_options)
            interval_menu.grid(row=row, column=1, padx=5, pady=5)
            row += 1
            # --- IP Request Limit ---
            tk.Label(content_frame, text="Set IP Request Limit (per hour):").grid(row=row, column=0, padx=5, pady=5, sticky='w')
            request_limit_var = tk.StringVar()
            request_limit_options = [10, 20, 30, 40, 50, 100, 300, 600, 1000, 1400, 2000]
            limit_menu = ttk.Combobox(content_frame, textvariable=request_limit_var, values=request_limit_options)
            limit_menu.grid(row=row, column=1, padx=5, pady=5)
            tk.Button(content_frame, text="Insert", command=lambda: update_setting("max_requests_per_ip")).grid(row=row, column=2, padx=5, pady=5)



            prev_hist={phone:prev_phone,time_limit:prev_time_limit,
                       max_requests_per_ip:prev_max_requests,
                       honeypot_ips:prev_honeypots,
                       folder_path:prev_sensative_folder
                       }
            for key,val in prev_hist.items():
                if val!=None:
                    key.insert(0,val) 





def update_setting(val):
    global admin_user, email, admin_pass,phone, time_limit, honeypot_ips, folder_path, allowed_ports, port_services
    global interval_var, request_limit_var,port,service
    dt=db()
    connection=dt[0]
    cursor=dt[1]
          
    if val=="sign in":
            a=messagebox.askyesno("confirm", "Are you sure you want to confirm it")
            if a:
                admin=admin_user.get()                
                em=email.get()
                pass_hs=hash_password(admin_pass.get())
                query = """ INSERT INTO Settings (admin_name,email,password_hash) VALUES (%s,%s,%s)"""
                cursor.execute(query, (admin,em,pass_hs))
                connection.commit()

                dashboardshow()
                validate_user=True    
    if val=="phone":
            print("yess")
            query = """ UPDATE Settings SET phone = %s  """
            cursor.execute(query, (phone.get(),))
            connection.commit()

    if val=="port_info":
            jsonins("port",port.get(),service.get())

    if val=="request_time_limit":
            query = """ UPDATE Settings SET request_time_limit = %s  """
            cursor.execute(query, (time_limit.get(),))
            connection.commit()
    if val=="max_requests_per_ip":
            jsonins("rqpt",interval_var.get(),request_limit_var.get())

    if val=="max_requests_per_ip_per_time":
            jsonins("rqpt",interval_var,request_limit_var)

    if val=="honeypot_ips":
            ins_honey(honeypot_ips.get())
    
    if val=="folder_path":
            query = """ UPDATE Settings SET sensitive_folders= %s """
            cursor.execute(query, (folder_path.get(),))
            connection.commit()
    if val=="allowed_port":
        
        query = """ UPDATE Settings SET allowed_ip = %s """
        cursor.execute(query, (allowed_ports.get(),))
        connection.commit()

def dashboardshow():
    
    for widget in content_frame.winfo_children():
        widget.destroy()
    show_pie_chart()
    global uname,pswd
    tk.Label(content_frame, text="DASHBOARD", font=("Arial", 18)).pack(pady=10)
    database=db()
    connection=database[0]
    cursor=database[1]
    # Checking if any admin exists
    cursor.execute("SELECT admin_name FROM settings")
    results = cursor.fetchall()




# Connect to my MySQL database
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="securegate"
         ,autocommit=True   # ✅ no transaction stays open
    )

def datamanage(page):
    if page=="Dashboard":
        return ["Dashboard"]
    if page =="IP Monitor":
       return ["IP","ip address"," request time","count of occur","blocked","block time","local ip","country","recent request"] 
    elif page=="Logs":
       return ["iprequest_junction","id","ip address","port number","protocol"," request time","count of occur"] 
    elif page=="Port Monitor":
        return ["request_type","port","service","request_count"," request time","is suspicious"]
    elif page=="Protocol Monitor":
        return ["Network_protocol","protocol","request_count"," first seen","last seen"]
    elif page=="blocked IP":
        return ["blocked IP","blocked ip","request_time","islocal","block interval"]
    elif page=="Setting":
        return ["Setting"]
    else:
        return []
def blockdatashow():
    database = db()
    conn=database[0]
    cursor =database[1]                                                                                                                       
    table_info = datamanage("blocked IP")
    cursor.execute("SELECT ip_address,request_time,is_local,block_time FROM ip where is_blocked=1")
    all_rows = cursor.fetchall()
    cursor.close()
    return all_rows


def data_to_show(page_name):
        clear_all_jobs()
        database=db()
        conn=database[0]
        cursor=database[1]
        # Checking if any admin exists
        cursor.execute("SELECT admin_name, password_hash FROM settings")
        results = cursor.fetchall()

        if not results:
            settingshow(1)
        else:
            global all_rows, columns, current_page

            for widget in content_frame.winfo_children():
                widget.destroy()

                conn = connect_db()
                cursor = conn.cursor()

                table_info = datamanage(page_name)
                if table_info:
                    table_name = table_info[0]
                    #print(table_name)
                    columns = table_info[1:]
                    if table_name=="blocked IP":
                        all_rows=blockdatashow()
                        show_page_data()

                    elif table_name=="Dashboard":
                        dashboardshow()
                    elif table_name=="Setting":
                        settingshow(3)



                    else:
                        cursor.execute(f"SELECT * FROM {table_name}")
                        all_rows=cursor.fetchall()
                        show_page_data()


                else:
                    for widget in content_frame.winfo_children():
                        widget.destroy()
                    
            #current_page = 0
            cursor.close()
            conn.close()
            print(page_name)
            if page_name!="Setting":
                global refresh_jobs
                # Schedule new job and store its ID
                job_id = root.after(5000, lambda: data_to_show(page_name))
                refresh_jobs.append(job_id)



def next_page():
    for widget in content_frame.winfo_children():
        widget.destroy()
    global current_page
    current_page += 1
    show_page_data()

def prev_page():
    for widget in content_frame.winfo_children():
        widget.destroy()
    global current_page
    current_page -= 1
    show_page_data()
    




def show_page(page_name):
        # Clear previous content
        for widget in content_frame.winfo_children():
            widget.destroy()

        label = tk.Label(content_frame, text=f"{page_name} Page", font=("Arial", 18), bg="white")
        label.pack(pady=20)
        

root = tk.Tk()
root.title("SecureGate")
root.geometry("1200x500")

sidebar = tk.Frame(root, width=150, bg="#2c3e50")
sidebar.pack(side="left", fill="y")

# Content area (Right panel)
content_frame = tk.Frame(root, bg="white")
content_frame.pack(side="right", expand=True, fill="both")

pages = ["Dashboard", "IP Monitor", "Port Monitor","Protocol Monitor","blocked IP", "Logs","Setting", "Exit"]



for widget in content_frame.winfo_children():
    widget.destroy()





def handle_button_click(n):
    if n == "Exit":
        root.quit()
    else:
        database=db()
        connection=database[0]
        cursor=database[1]
        # Checking if any admin exists
        cursor.execute("SELECT admin_name FROM settings")
        results = cursor.fetchall()
        print(results)
        if not results:
            settingshow(1)
        if validate_user is not True:
            settingshow(2)
        else:

            data_to_show(n) 

# Create buttons in sidebar
for name in pages:
    btn = tk.Button(
        sidebar,
        text=name,
        fg="white",
        bg="#34495e",
        font=("Arial", 12),
        relief="flat",
        command=partial(handle_button_click, name)      #imp
    )
    btn.pack(fill="x", pady=2)



settingshow(2)
def show_page_data():
    global all_rows, columns, current_page

    start = current_page * rows_per_page
    end = start + rows_per_page
    rows = all_rows[start:end]

    for widget in content_frame.winfo_children():
        widget.destroy()

    # Headers
    for i, col in enumerate(columns):
        tk.Label(content_frame, text=col, font=("Arial", 10, "bold"), 
                 relief="solid", borderwidth=1, width=20).grid(row=0, column=i, sticky="nsew", padx=0, pady=0)

    # Rows
    for row_index, row in enumerate(rows):
        for col_index, cell in enumerate(row):
            tk.Label(content_frame, text=str(cell), 
                     relief="solid", borderwidth=1, width=20).grid(row=row_index + 1, column=col_index, sticky="nsew", padx=0, pady=0)

    # Navigation frame
    nav = tk.Frame(content_frame)
    nav.grid(row=len(rows) + 1, columnspan=len(columns), pady=10)

    if current_page > 0:
        tk.Button(nav, text="Previous", command=prev_page).pack(side="left", padx=1)
    if end < len(all_rows):
        tk.Button(nav, text="Next", command=next_page).pack(side="left", padx=1)

#  application run krayla
root.mainloop()

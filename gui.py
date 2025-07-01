import tkinter as tk
from tkinter import ttk
import mysql.connector
from functools import partial #buttonclick command
from tkinter import messagebox
import time
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

validate_user=False
current_page = 0
rows_per_page = 15
all_rows = []
columns = []



def db():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="securegate"
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





def show_pie_chart():
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




global admin_user, email, admin_pass,phone, time_limit, honeypot_ips,max_requests_per_ip, folder_path, allowed_ports, port_services
global interval_var, request_limit_var


def fetch_settings_data():
    dt = db()
    connection, cursor = dt
    cursor.execute("""
        SELECT 
            phone, 
            request_time_limit, 
            max_requests_per_ip, 
            honeypot_ips, 
            sensitive_folders, 
        upload_folder 
        FROM settings 
        LIMIT 1
                """)
    result = cursor.fetchone()
    return result



def settingshow(setnum):
    global admin_user, email, admin_pass,phone,max_requests_per_ip, time_limit, honeypot_ips, folder_path, allowed_ports, port_services
    global interval_var, request_limit_var


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

        tk.Button(content_frame, text="Confirm Settings", command=lambda: update_settings("sign in"), bg="green", fg="white").pack(pady=15)
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
        result=fetch_settings_data()
        # Fetch previous values safely
        prev_phone = result[0] 
        prev_time_limit = result[1] 
        prev_max_requests = result[2] 
        prev_honeypots = result[3]
        prev_sensative_folder=result[4]
        # --- Admin Phone ---
        tk.Label(content_frame, text="Admin Mobile Number").pack(pady=5)
        phone = tk.Entry(content_frame)
        phone.pack(pady=5)

        tk.Button(content_frame, text="Submit", command=lambda: update_setting("phone")).pack()

        # --- Request Time Limit ---
        tk.Label(content_frame, text="Request Time Limit (in minutes)").pack(pady=5)
        time_limit = tk.Entry(content_frame)
        time_limit.pack(pady=5)
        tk.Button(content_frame, text="Submit", command=lambda: update_setting("request_time_limit")).pack()

        # --- Max Requests Per IP ---
        tk.Label(content_frame, text="Max Requests Per IP (per hour)").pack(pady=5)
        max_requests_per_ip = tk.Entry(content_frame)
        max_requests_per_ip.pack(pady=5)
        tk.Button(content_frame, text="Submit", command=lambda: update_setting("max_requests_per_ip")).pack()

        # --- Honeypot IPs ---
        tk.Label(content_frame, text="Honeypot IPs (comma-separated)").pack(pady=5)
        honeypot_ips = tk.Entry(content_frame)
        honeypot_ips.pack(pady=5)
        tk.Button(content_frame, text="Submit", command=lambda: update_setting("honeypot_ips")).pack()

        # --- Folder Path ---
        tk.Label(content_frame, text="Encrypted Folder Path(s)").pack(pady=5)
        folder_path = tk.Entry(content_frame)
        folder_path.pack(pady=5)
        tk.Button(content_frame, text="Submit", command=lambda: update_setting("sensitive_folders")).pack()
'''
        # --- Allowed Ports ---
        tk.Label(content_frame, text="Allowed Ports (JSON format)").pack(pady=5)
        allowed_ports = tk.Entry(content_frame)
        allowed_ports.pack(pady=5)
        tk.Button(content_frame, text="Submit", command=lambda: update_setting("allowed_ports", allowed_ports.get())).pack()

        # --- Port Services ---
        tk.Label(content_frame, text="Port Services (JSON format)").pack(pady=5)
        port_services = tk.Entry(content_frame)
        port_services.pack(pady=5)
        tk.Button(content_frame, text="Submit", command=lambda: update_setting("allowed_ports", port_services.get())).pack()

        # --- Time Interval ---
        tk.Label(content_frame, text="Select Time Interval (minutes):").pack(pady=5)
        global interval_var
        interval_var = tk.StringVar()
        interval_options = [1, 2, 3, 4, 5, 10, 30, 60, 120]
        interval_menu = ttk.Combobox(content_frame, textvariable=interval_var, values=interval_options)
        interval_menu.pack()
        tk.Button(content_frame, text="Insert", command=lambda: update_setting("request_time_limit", interval_var.get())).pack()

        # --- IP Request Limit ---
        tk.Label(content_frame, text="Set IP Request Limit (per hour):").pack(pady=5)
        global request_limit_var
        request_limit_var = tk.StringVar()
        request_limit_options = [10, 20, 30, 40, 50, 100, 300, 600, 1000, 1400, 2000]
        limit_menu = ttk.Combobox(content_frame, textvariable=request_limit_var, values=request_limit_options)
        limit_menu.pack()
        tk.Button(content_frame, text="Insert", command=lambda: update_setting("max_requests_per_ip", request_limit_var.get())).pack()
'''





def update_setting(val):
    global admin_user, email, admin_pass,phone, time_limit, honeypot_ips, folder_path, allowed_ports, port_services
    global interval_var, request_limit_var
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

    
    if val=="request_time_limit":
            query = """ UPDATE Settings SET request_time_limit = %s  """
            cursor.execute(query, (time_limit.get(),))
            connection.commit()
    if val=="max_requests_per_ip":
            query = """ UPDATE Settings SET max_requests_per_ip = %s  """
            cursor.execute(query, (max_requests_per_ip.get(),))
            connection.commit()    
    if val=="honeypot_ips":
            query = """UPDATE Settings SET honeypot_ips = %s """
            cursor.execute(query, (honeypot_ips.get(),))
            connection.commit()
    
    if val=="upload_folders":
            query = """ UPDATE Settings SET upload_folders = %s """
            cursor.execute(query, (folder_path.get(),))
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
    )

def datamanage(page):
    if page=="Dashboard":
        return ["Dashboard"]
    if page =="IP Monitor":
       return ["IP","ip address"," request time","count of occur","blocked","block time","local ip","country"] 
    elif page=="Logs":
       return ["iprequest_junction","id","ip address","port number"," request time","count of occur"] 
    elif page=="Port Monitor":
        return ["request_type","port","service","request count"," request time","is suspicious"]
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
        database=db()
        connection=database[0]
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

pages = ["Dashboard", "IP Monitor", "Port Monitor","blocked IP", "Logs","Setting", "Exit"]



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




def show_page_data():
    global all_rows, columns, current_page

    start = current_page * rows_per_page
    end = start + rows_per_page
    rows = all_rows[start:end]

    for widget in content_frame.winfo_children():
        widget.destroy()

    # Headers
    header_frame = tk.Frame(content_frame)
    header_frame.pack()
    for col in columns:
        tk.Label(header_frame, text=col, font=("Arial", 10, "bold"), width=20, relief="ridge").pack(side="left")

    # Rows
    for row in rows:
        row_frame = tk.Frame(content_frame)
        row_frame.pack()
        for cell in row:
            tk.Label(row_frame,text=str(cell),width=20,relief="groove").pack(side="left")

    nav = tk.Frame(content_frame)
    nav.pack(pady=10)

    if current_page > 0:
        tk.Button(nav,text="Previous",command=prev_page).pack(side="left", padx=1)
    if end < len(all_rows):
        tk.Button(nav,text="Next",command=next_page).pack(side="left", padx=1)





settingshow(2)


#  application run krayla
root.mainloop()

import tkinter as tk
from tkinter import ttk
import mysql.connector
from functools import partial #buttonclick command
from tkinter import messagebox
import time
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import json
from tkinter import ttk


validate_user=False
current_page = 0
rows_per_page = 15
all_rows = []
columns = []

global connection,cursor

refresh_jobs = []  # List to store job IDs

def clear_all_jobs():
    global refresh_jobs
    for job_id in refresh_jobs:
        root.after_cancel(job_id)
    refresh_jobs.clear()



def db():
    try:
        global connection,cursor
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="securegate"
             ,autocommit=True   
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









def custom_askyesno(title, message):
    result = [False]
    dialog = tk.Toplevel()
    dialog.title(title)
    dialog.configure(bg="#2E2E2E") 
    dialog.geometry("400x180")
    dialog.resizable(False, False)
    dialog.transient(root)
    dialog.grab_set()
    style = ttk.Style()
    style.configure("Yes.TButton", font=("Helvetica", 12, "bold"), background="#4CAF50", foreground="black")
    style.map("Yes.TButton", background=[('active', '#45a049')])
    
    style.configure("No.TButton", font=("Helvetica", 12), background="#f44336", foreground="black")
    style.map("No.TButton", background=[('active', '#e53935')])
    def on_yes():
        result[0] = True
        dialog.destroy()

    def on_no():
        result[0] = False
        dialog.destroy()
    main_frame = tk.Frame(dialog, bg="#2E2E2E")
    main_frame.pack(expand=True, fill="both", padx=20, pady=20)
    
    message_label = tk.Label(
        main_frame,
        text=message,
        font=("Helvetica", 14),
        wraplength=360, 
        justify="center",
        bg="#2E2E2E",
        fg="white"
    )
    message_label.pack(pady=(0, 25))

    button_frame = tk.Frame(main_frame, bg="#2E2E2E")
    button_frame.pack()

    yes_button = ttk.Button(button_frame, text="Yes, Confirm", style="Yes.TButton", command=on_yes)
    yes_button.pack(side="left", padx=10, ipady=5)
    
    no_button = ttk.Button(button_frame, text="No, Cancel", style="No.TButton", command=on_no)
    no_button.pack(side="left", padx=10, ipady=5)

    root.wait_window(dialog)

    return result[0]



def fetch_ips(tp):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="securegate"
         ,autocommit=True  
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




import requests
def get_country(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data.get("status") == "fail":
            return "Unknown"
        return data.get("country", "Unknown")
    except Exception as e:
        print(f"Error: {str(e)}")
        return "Unknown"

def update_null_countries(conn, cursor):
    """
    Finds IPs with a NULL country field and updates them.
    If the country cannot be determined via the API, it sets the value to 'country not set'.
    """
    try:
        # Find all IPs where the country is NULL
        cursor.execute("SELECT ip_address FROM ip WHERE country IS NULL")
        null_ips = cursor.fetchall()
        
        if not null_ips:
            print("No IPs found with a NULL country field.")
            return

        print(f"Found {len(null_ips)} IPs with a NULL country field. Updating...")

        for ip_tuple in null_ips:
            ip_address = ip_tuple[0]
            
            # Get the country from the API
            api_country = get_country(ip_address)
            
            country_to_set = api_country
            cursor.execute(
                "UPDATE ip SET country = %s WHERE ip_address = %s",
                (country_to_set, ip_address)
            )
            print(f"Updated IP {ip_address} to country: {country_to_set}")

        conn.commit()
        print("Successfully updated all countries.")
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        conn.rollback() 
        
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


import bcrypt

def hash_password(plain_password):

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  




import collections
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def show_bar_chart_by_country():
    blocked = fetch_ips("blocked") or []
    unblocked = fetch_ips("unblocked") or []

    for widget in content_frame.winfo_children():
        widget.destroy()

    blocked_counts = collections.defaultdict(int)
    for ip, country in blocked:
        # Normalize country names: handle None, empty strings, and whitespace
        if country is None or str(country).strip() == "":
            country_name = "Unknown"
        else:
            country_name = str(country).strip() # Ensure it's a string and strip whitespace
        blocked_counts[country_name] += 1

    unblocked_counts = collections.defaultdict(int)
    for ip, country in unblocked:
        # Normalize country names
        if country is None or str(country).strip() == "":
            country_name = "Unknown"
        else:
            country_name = str(country).strip()
        unblocked_counts[country_name] += 1

    all_countries = sorted(list(set(blocked_counts.keys()) | set(unblocked_counts.keys())))

    # Handle the case where there's no data at all
    if not all_countries:
        tk.Label(content_frame, text="No country data available to display chart.", font=("Arial", 14)).pack(pady=20)
        return

    blocked_values = [blocked_counts.get(country, 0) for country in all_countries]
    unblocked_values = [unblocked_counts.get(country, 0) for country in all_countries]

    fig, ax = plt.subplots(figsize=(10, 6)) # Increased figure size slightly for better readability
    width = 0.35
    x = range(len(all_countries))

    rects1 = ax.bar(x, blocked_values, width, label='Blocked', color='red')
    rects2 = ax.bar([i + width for i in x], unblocked_values, width, label='Unblocked', color='green')

    ax.set_ylabel('Number of IPs')
    ax.set_title('Blocked vs Unblocked IPs by Country')
    ax.set_xticks([i + width / 2 for i in x])
    ax.set_xticklabels(all_countries, rotation=45, ha='right') # Rotate labels for better fit
    ax.legend()
    fig.tight_layout() # Adjust layout to prevent labels from overlapping

    canvas = FigureCanvasTkAgg(fig, master=content_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=20, fill="both", expand=True)

    # --- Treeview Section ---
    summary_frame = ttk.Frame(content_frame)
    summary_frame.pack(fill='both', expand=True, padx=10, pady=5)

    columns = ('country', 'blocked', 'unblocked')
    tree = ttk.Treeview(summary_frame, columns=columns, show='headings', height=7)

    tree.heading('country', text='Country')
    tree.column('country', anchor='w', width=150)

    tree.heading('blocked', text='Blocked')
    tree.column('blocked', anchor='center', width=80)

    tree.heading('unblocked', text='Unblocked')
    tree.column('unblocked', anchor='center', width=80)

    scrollbar = ttk.Scrollbar(summary_frame, orient='vertical', command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    scrollbar.pack(side='right', fill='y')
    tree.pack(side='left', fill='both', expand=True)

    for country in all_countries:
        blocked_count = blocked_counts.get(country, 0)
        unblocked_count = unblocked_counts.get(country, 0)
        tree.insert('', 'end', values=(country, blocked_count, unblocked_count))




global admin_user, email, admin_pass,phone, time_limit, honeypot_ips,max_requests_per_ip, folder_path, allowed_ports, port_services,form_container
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
        json_data = result[0] if result else None
        honeypot_dict = json.loads(json_data) if json_data else {}

        key = str(data)
        new_value = data2
        
        should_save_to_db = True 
        
        if key in honeypot_dict:
            existing_value = honeypot_dict[key]
            overwrite = messagebox.askyesno(
                "Duplicate Entry",
                icon=messagebox.WARNING,
                message=f"The key '{key}' already exists.",
                detail=f"Its current value is '{existing_value}'.\n\nDo you want to overwrite it with '{new_value}'?"
            )
            
            if overwrite:
                honeypot_dict[key] = new_value
            else:
                should_save_to_db = False
                print("Update cancelled by user.")

        else:
            honeypot_dict[key] = new_value
            print(f"New key '{key}' added.")

        if should_save_to_db:
            # Convert the dictionary back to a JSON string
            updated_json = json.dumps(honeypot_dict)
            
            # Execute the update with the properly formatted JSON string
            cursor.execute("UPDATE settings SET max_requests_per_ip = %s limit 1", (updated_json,))
            conn.commit()
            print("Database has been updated.")
        
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
    global admin_user, email, admin_pass,phone,max_requests_per_ip, time_limit, honeypot_ips, folder_path, allowed_ports, port_services,form_container
    global interval_var, request_limit_var ,port,service


    '''

    1 for admin sign in
    2 for admin log in
    3 for other info taking
    '''
    for widget in content_frame.winfo_children():
        widget.destroy()
    if setnum == 1:
        sidebar.pack_forget()
        form_container = ttk.Frame(root, padding="10")
        form_container.pack(expand=True)
        settings_group = ttk.LabelFrame(form_container, text="Admin Account Setup", padding="15 10")
        settings_group.grid(row=0, column=0, sticky="ew")
        settings_group.columnconfigure(1, weight=1)

        ttk.Label(settings_group, text="Admin Username").grid(row=0, column=0, padx=5, pady=10, sticky="w")
        admin_user = ttk.Entry(settings_group, width=30)
        admin_user.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        ttk.Label(settings_group, text="Admin Email").grid(row=1, column=0, padx=5, pady=10, sticky="w")
        email = ttk.Entry(settings_group)
        email.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        ttk.Label(settings_group, text="Admin Password").grid(row=2, column=0, padx=5, pady=10, sticky="w")
        admin_pass = ttk.Entry(settings_group, show="*")
        admin_pass.grid(row=2, column=1, padx=5, pady=10, sticky="ew")
        
        ttk.Label(settings_group, text="Confirm Password").grid(row=3, column=0, padx=5, pady=10, sticky="w")
        confirm_pass = ttk.Entry(settings_group, show="*")
        confirm_pass.grid(row=3, column=1, padx=5, pady=10, sticky="ew")

        confirm_button = ttk.Button(form_container, text="Confirm Settings", command=lambda: update_setting("sign in"))
        confirm_button.grid(row=1, column=0, pady=20)
    if setnum==2:
        sidebar.pack_forget()
        database=db()
        connection=database[0]
        cursor=database[1]
        cursor.execute("SELECT admin_name, password_hash FROM settings")
        results = cursor.fetchall()

        if not results:
            settingshow(1)
        else:
            login_container = ttk.Frame(content_frame)
            login_container.pack(expand=True)

            login_group = ttk.LabelFrame(login_container, text="Admin Login", padding=(20, 10))
            login_group.pack(padx=20, pady=20)

            login_group.columnconfigure(1, weight=1)

            ttk.Label(login_group, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
            admin_user = ttk.Entry(login_group, width=30, font=("Helvetica", 11))
            admin_user.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

            ttk.Label(login_group, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
            admin_pass = ttk.Entry(login_group, show="*", font=("Helvetica", 11))
            admin_pass.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
            
            submit_button = ttk.Button(login_container, 
                                    text="Submit", 
                                    command=lambda: validate(admin_user.get(), admin_pass.get()))
            submit_button.pack(pady=(0, 20), ipady=5)
            
    if setnum == 3:
        
        style = ttk.Style()
        style.configure("TLabelFrame.Label", font=("Helvetica", 12, "bold"))

        settings_container = ttk.Frame(content_frame, padding=10)
        settings_container.pack(fill="both", expand=True)

        general_group = ttk.LabelFrame(settings_container, text="General", padding=15)
        general_group.pack(fill="x", padx=10, pady=5)
        general_group.columnconfigure(1, weight=1)
        
        ttk.Label(general_group, text="Admin Mobile Number:").grid(row=0, column=0, padx=5, pady=8, sticky='w')
        phone = ttk.Entry(general_group)
        phone.grid(row=0, column=1, padx=5, pady=8, sticky='ew')
        ttk.Button(general_group, text="Update", command=lambda: update_setting("phone")).grid(row=0, column=2, padx=5, pady=8)
        limit_group = ttk.LabelFrame(settings_container, text="Rate Limiting", padding=15)
        limit_group.pack(fill="x", padx=10, pady=5)
        limit_group.columnconfigure(1, weight=1)

        ttk.Label(limit_group, text="Time Interval (minutes):").grid(row=0, column=0, padx=5, pady=8, sticky='w')
        interval_var = tk.StringVar()
        interval_options = [1, 2, 3, 4, 5, 10, 30, 60, 120]
        interval_menu = ttk.Combobox(limit_group, textvariable=interval_var, values=interval_options, state="readonly")
        interval_menu.grid(row=0, column=1, padx=5, pady=8, sticky='ew')

        ttk.Label(limit_group, text="IP Request Limit (per interval):").grid(row=1, column=0, padx=5, pady=8, sticky='w')
        request_limit_var = tk.StringVar()
        request_limit_options = [10, 20, 30, 40, 50, 100, 300, 600, 1000, 1400, 2000]
        limit_menu = ttk.Combobox(limit_group, textvariable=request_limit_var, values=request_limit_options, state="readonly")
        limit_menu.grid(row=1, column=1, padx=5, pady=8, sticky='ew')
        ttk.Button(limit_group, text="Update", command=lambda: update_setting("max_requests_per_ip")).grid(row=1, column=2, padx=5, pady=8)

        ttk.Label(limit_group, text="Max Requests Per IP (legacy):").grid(row=2, column=0, padx=5, pady=8, sticky='w')
        max_requests_per_ip = ttk.Entry(limit_group)
        max_requests_per_ip.grid(row=2, column=1, padx=5, pady=8, sticky='ew')
        ttk.Button(limit_group, text="Update", command=lambda: update_setting("max_requests_per_ip")).grid(row=2, column=2, padx=5, pady=8)
        
        security_group = ttk.LabelFrame(settings_container, text="Security & Network", padding=15)
        security_group.pack(fill="x", padx=10, pady=5)
        security_group.columnconfigure(1, weight=1)
        
        ttk.Label(security_group, text="Honeypot IPs:").grid(row=0, column=0, padx=5, pady=8, sticky='w')
        honeypot_ips = ttk.Entry(security_group)
        honeypot_ips.grid(row=0, column=1, padx=5, pady=8, sticky='ew')
        ttk.Button(security_group, text="Update", command=lambda: update_setting("honeypot_ips")).grid(row=0, column=2, padx=5, pady=8)

        result = fetch_settings_data()
        prev_phone, prev_time_limit, prev_max_requests, prev_honeypots, prev_sensative_folder = result[:5] if result else (None, None, None, None, None)
        
        prev_hist = {
            phone: prev_phone,
            max_requests_per_ip: prev_max_requests,
            honeypot_ips: prev_honeypots,
        }
        
        for widget, value in prev_hist.items():
            if value is not None:
                widget.insert(0, value)




def update_setting(val):
    global admin_user, email,form_container, admin_pass,phone, time_limit, honeypot_ips, folder_path, allowed_ports, port_services
    global interval_var, request_limit_var,port,service
    dt=db()
    connection=dt[0]
    cursor=dt[1]
    
    if val=="sign in":
            a=custom_askyesno("Admin Registration","Do you want to confirm it")
            if a:
                admin=admin_user.get()                
                em=email.get()
                pass_hs=hash_password(admin_pass.get())
                query = """ INSERT INTO Settings (admin_name,email,password_hash) VALUES (%s,%s,%s)"""
                cursor.execute(query, (admin,em,pass_hs))
                connection.commit()

                dashboardshow()
                if form_container:
                    form_container.destroy()
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
    sidebar.pack()
    global connection,cursor
    for widget in content_frame.winfo_children():
        widget.destroy()
    tk.Label(content_frame, text="DASHBOARD", font=("Arial", 18)).pack(pady=10)
    database=db()
    connection=database[0]
    cursor=database[1]
    cursor.execute("SELECT admin_name FROM settings")
    results = cursor.fetchall()
    show_bar_chart_by_country()
    thread = threading.Thread(target=update_null_countries, args=(connection, cursor))
    thread.daemon = True # This ensures the thread exits when the main program does
    thread.start()
    global refresh_jobs
    job_id = root.after(5000, lambda: data_to_show("Dashboard"))
    refresh_jobs.append(job_id)
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="securegate"
         ,autocommit=True  
    )

def datamanage(page):
    if page=="Dashboard":
        return ["Dashboard"]
    if page =="IP Monitor":
       return ["IP","ip address"," request time","count of occur","blocked","block time","local ip","country","recent request"] 
    elif page=="Logs":
       return ["iprequest_junction","id","ip address","port number","protocol"," request time"] 
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







import threading

def fetch_data_in_thread(page_name):
    global columns
    """Function to be run in a separate thread to fetch data."""
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        table_info = datamanage(page_name)
        fetched_rows = None
        if table_info:
            table_name = table_info[0]
            if table_name == "blocked IP":
                fetched_rows = blockdatashow()
            elif table_name == "Dashboard":
                fetched_rows = "dashboard" # Special signal
            elif table_name == "Setting":
                fetched_rows = "settings" # Special signal
            else:
                cursor.execute(f"SELECT * FROM {table_name}")
                fetched_rows = cursor.fetchall()
        
        root.after(0, lambda: update_gui_with_data(fetched_rows,table_info[1:], page_name))
        
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Error in data fetching thread: {e}")

def update_gui_with_data(fetched_rows, cols, page_name):
    global columns
    """Function to safely update the GUI with fetched data."""
    global all_rows, columns, current_page
    
    if fetched_rows == "dashboard":
        dashboardshow()
        return
    elif fetched_rows == "settings":
        settingshow(3)
        return

    all_rows = fetched_rows if fetched_rows is not None else []
    columns = cols
    current_page = 0
    show_page_data()
    
    if page_name != "Setting":
        global refresh_jobs
        job_id = root.after(5000, lambda: data_to_show(page_name))
        refresh_jobs.append(job_id)

def data_to_show(page_name):
    """Main function called by button clicks."""
    global validate_user
    
    clear_all_jobs()
    
    thread = threading.Thread(target=fetch_data_in_thread, args=(page_name,))
    thread.daemon = True
    thread.start()










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
        

try:
    from ttkthemes import ThemedTk
    root = ThemedTk(theme="arc")
except ImportError:
    print("ttkthemes not found. Using the 'clam' theme as a fallback.")
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('clam')

root.title("SecureGate Network Monitor")
try:
    root.iconbitmap("securegate_image.ico")
except tk.TclError:
    print("Icon not found. Skipping.")

INITIAL_WIDTH = 1100
INITIAL_HEIGHT = 700
root.geometry(f"{INITIAL_WIDTH}x{INITIAL_HEIGHT}")
root.minsize(800, 600)

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x_coordinate = int((screen_width / 2) - (INITIAL_WIDTH / 2))
y_coordinate = int((screen_height / 2) - (INITIAL_HEIGHT / 2))
root.geometry(f"+{x_coordinate}+{y_coordinate}")
root.columnconfigure(1, weight=1)
root.rowconfigure(0, weight=1)












sidebar = tk.Frame(root, width=150, bg="#2c3e50")
sidebar.pack(side="left", fill="y")

content_frame = tk.Frame(root,bg="white")
content_frame.pack(side="right",expand=True,fill="both")

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

for name in pages:
    btn = tk.Button(
    sidebar,
    text=name,
    fg="white",
    bg="#34495e", # Original color
    font=("Arial", 12),
    relief="flat",
    activebackground="#4a6572", # Color when button is clicked
    activeforeground="white",
    command=partial(handle_button_click, name)
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
    style = ttk.Style()
    style.configure("Treeview.Heading", font=("Arial", 11, "bold"))
    style.configure("Treeview", rowheight=28, font=("Arial", 10))

    # Create the Treeview widget (the table)
    tree = ttk.Treeview(content_frame, columns=columns, show='headings')


    if not rows:
        no_data_label = ttk.Label(
        content_frame, 
        text="No Data Found Here",
        font=("Arial", 18),
        foreground="gray" # Use a muted color for the text
    )
        no_data_label.pack(expand=True)
    else:
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor="center", width=120)

        tree.tag_configure('oddrow', background='#f0f0f0') # Light gray for odd rows
        tree.tag_configure('evenrow', background='white')   # White for even rows

        for row_index, row in enumerate(rows):
            processed_row = [cell if cell not in [None, 0, "None"] else '-' for cell in row]
            if row_index % 2 == 0:
                tree.insert('', 'end', values=processed_row, tags=('evenrow',))
            else:
                tree.insert('', 'end', values=processed_row, tags=('oddrow',))

        # Place the Treeview in the grid and make it expandable
        tree.grid(row=0, column=0, sticky="nsew")
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")
        if len(columns) == 0:
            span = 1
        else:
            span = len(columns)
            
        nav = tk.Frame(content_frame)
        nav.grid(row=len(rows) + 1, columnspan=span, pady=10)

        if current_page>0:
            tk.Button(nav, text="Previous", command=prev_page).pack(side="left", padx=1)
        if end<len(all_rows):
            tk.Button(nav,text="Next", command=next_page).pack(side="left", padx=1)



root.mainloop()





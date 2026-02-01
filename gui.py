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
from PIL import Image, ImageTk





# ==================================================
# SecureGate GUI – Environment Loader (SAFE)
# ==================================================

import os
from dotenv import load_dotenv

# Resolve base directory safely (works when launched from installer / service)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_FILE = os.path.join(BASE_DIR, "securegate.env")

# Load .env with override (CRITICAL)
load_dotenv(ENV_FILE, override=True)

# -------------------------------
# DATABASE CONFIG
# -------------------------------
SECUREGATE_DB_HOST = os.getenv("SECUREGATE_DB_HOST", "localhost")
SECUREGATE_DB_PORT = int(os.getenv("SECUREGATE_DB_PORT", "3306"))
SECUREGATE_DB_USER = os.getenv("SECUREGATE_DB_USER", "root")
SECUREGATE_DB_PASS = os.getenv("SECUREGATE_DB_PASS", "")
SECUREGATE_DB_NAME = os.getenv("SECUREGATE_DB_NAME", "securegate")

# -------------------------------
# GUI CONFIG
# -------------------------------
SECUREGATE_GUI_REFRESH_INTERVAL = int(
    os.getenv("SECUREGATE_GUI_REFRESH_INTERVAL", "10")
)

SECUREGATE_GUI_ROWS_PER_PAGE = int(
    os.getenv("SECUREGATE_GUI_ROWS_PER_PAGE", "15")
)

SECUREGATE_GUI_WIDTH = int(
    os.getenv("SECUREGATE_GUI_WIDTH", "1100")
)

SECUREGATE_GUI_HEIGHT = int(
    os.getenv("SECUREGATE_GUI_HEIGHT", "700")
)

SECUREGATE_GUI_ICON = os.getenv(
    "SECUREGATE_GUI_ICON", "securegate_image.ico"
)

# -------------------------------
# NETWORK / API CONFIG
# -------------------------------
SECUREGATE_GEOIP_API = os.getenv(
    "SECUREGATE_GEOIP_API", "http://ip-api.com/json"
)








RUN_ENGINE=False
validate_user=False
current_page = 0
rows_per_page =  SECUREGATE_GUI_ROWS_PER_PAGE
all_rows = []
columns = []
import re


# The Global App State
APP_STATE = {
    "current_view": "dashboard", # Tracks which page the user is on
    "current_page": 0,           # Tracks pagination
    "rows_per_page": SECUREGATE_GUI_ROWS_PER_PAGE,
    "search_query": "",          # Tracks if user filtered data
    "last_data_type": "logs"     # Tracks if we were looking at blocked or unblocked
}



refresh_jobs = []  # List to store job IDs
def global_refresh_job():
    global refresh_jobs, APP_STATE
    
    # 1. Clear existing jobs to prevent stacking
    clear_all_jobs()

    # 2. Refresh logic based on active view
    current_v = APP_STATE["current_view"]
    
    if current_v == "dashboard":
        dashboardshow()
    elif current_v == "data_logs":
        # We don't change the data_type, just re-fetch for the current one
        data_to_show(APP_STATE.get("last_page_name", "Logs"))

    # 3. Schedule next refresh and save ID
    new_job = root.after(SECUREGATE_GUI_REFRESH_INTERVAL * 1000, global_refresh_job)

    refresh_jobs.append(new_job)
def clear_all_jobs():
    """Stops all scheduled background refresh tasks to prevent stacking."""
    global refresh_jobs
    for job in refresh_jobs:
        try:
            root.after_cancel(job)
        except Exception:
            pass
    refresh_jobs.clear()
def db():
    try:
        # 🔁 ALWAYS reload env (critical)
        load_dotenv(ENV_FILE, override=True)

        host = os.getenv("SECUREGATE_DB_HOST")
        user = os.getenv("SECUREGATE_DB_USER")
        password = os.getenv("SECUREGATE_DB_PASS")
        database = os.getenv("SECUREGATE_DB_NAME")
        port = int(os.getenv("SECUREGATE_DB_PORT", "3306"))

        if not all([host, user, database]):
            raise ValueError("Database environment variables missing")

        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            port=port,
            autocommit=True
        )
        return conn, conn.cursor()

    except Exception as e:
        print("SQL Error:", e)
        return None, None

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
    #please change it later:
    result=True

    #
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
        host=os.getenv("SECUREGATE_DB_HOST"),
        user=os.getenv("SECUREGATE_DB_USER"),
        password=os.getenv("SECUREGATE_DB_PASS"),
        database=os.getenv("SECUREGATE_DB_NAME"),
        port=int(os.getenv("SECUREGATE_DB_PORT", "3306")),
        autocommit=True
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
        response =requests.get(f"{SECUREGATE_GEOIP_API}/{ip}")
        data = response.json()
        if data.get("status") == "fail":
            return "Unknown"
        return data.get("country", "Unknown")
    except Exception as e:
        print(f"Error: {str(e)}")
        return "Unknown"

def update_null_countries():
    try:
        conn = connect_db()
        if not conn:
            return

        cursor = conn.cursor()

        cursor.execute("SELECT ip_address FROM ip WHERE country IS NULL")
        null_ips = cursor.fetchall()

        for (ip,) in null_ips:
            country = get_country(ip)
            cursor.execute(
                "UPDATE ip SET country=%s WHERE ip_address=%s",
                (country, ip)
            )

        conn.commit()

    except Exception as e:
        print("update_null_countries error:", e)

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

import bcrypt

def hash_password(plain_password):

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  




import collections
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
global admin_user, email, admin_pass,phone, time_limit, honeypot_ips,max_requests_per_ip,folder_path, allowed_ports, port_services,form_container,image_container,whitelist,blacklist,email_notify_var
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
    global admin_user, email, admin_pass, phone, max_requests_per_ip, time_limit, honeypot_ips
    global sensative_folder, folder_path, allowed_ports, port_services, form_container
    global image_container, new_email, whitelist, blacklist, interval_var, request_limit_var 
    global port, service, email_notify_var

    # --- THE CRITICAL FIX: STOP BACKGROUND AUTO-REFRESH ---
    # This prevents the Dashboard timer from clearing your Settings UI
    clear_all_jobs() 
    
    # Update state so the global background job knows you are in Settings
    APP_STATE["current_view"] = "Setting"

    # Clear existing widgets to prepare the new view
    for widget in content_frame.winfo_children():
        widget.destroy()

    # ================= SETNUM 1: ADMIN SIGN IN =================
    if setnum == 1:
        BG_COLOR, CARD_BG, ACCENT_BLUE, TEXT_DIM = "#f4f7f6", "#ffffff", "#3498db", "#7f8c8d"
        style = ttk.Style(root)
        style.configure("Registration.TFrame", background=BG_COLOR)
        
        main_container = tk.Frame(content_frame, bg=BG_COLOR)
        main_container.pack(fill="both", expand=True)

        form_container = tk.Frame(main_container, bg=BG_COLOR, padx=40)
        form_container.pack(side="left", fill="y", pady=40)

        setup_card = tk.LabelFrame(form_container, text=" ACCOUNT INITIALIZATION ", 
                                   font=("Segoe UI", 10, "bold"), fg=ACCENT_BLUE, bg=CARD_BG,
                                   padx=30, pady=30, relief="flat", highlightthickness=1, 
                                   highlightbackground="#dcdde1")
        setup_card.pack(fill="both", expand=True)

        def create_input(parent, label_text, is_pass=False):
            tk.Label(parent, text=label_text, font=("Segoe UI", 9), fg=TEXT_DIM, bg=CARD_BG).pack(anchor="w", pady=(10, 0))
            entry = ttk.Entry(parent, font=("Segoe UI", 11), show="*" if is_pass else "")
            entry.pack(fill="x", pady=(5, 10), ipady=3)
            return entry

        admin_user = create_input(setup_card, "Admin Username")
        email = create_input(setup_card, "Email Address")
        admin_pass = create_input(setup_card, "Create Password", is_pass=True)
        confirm_pass = create_input(setup_card, "Confirm Password", is_pass=True)

        confirm_button = tk.Button(form_container, text="CREATE ADMIN ACCOUNT", command=lambda: update_setting("sign in"),
                                   font=("Segoe UI", 10, "bold"), bg=ACCENT_BLUE, fg="white", relief="flat", 
                                   cursor="hand2", padx=20, pady=10, activebackground="#2980b9")
        confirm_button.pack(fill="x", pady=20)

        image_container = tk.Frame(main_container, bg="#F2F4F7")
        image_container.pack(side="right", expand=True, fill="both")
        try:
            original_image = Image.open("securegate_.png")
            def resize_image(event):
                new_width, new_height = event.width, event.height
                if new_width <= 0 or new_height <= 0: return
                original_aspect = original_image.width / original_image.height
                container_aspect = new_width / new_height
                if container_aspect > original_aspect:
                    height = new_height
                    width = int(height * original_aspect)
                else:
                    width = new_width
                    height = int(width / original_aspect)
                resized_image = original_image.resize((width, height), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(resized_image)
                image_label.config(image=photo); image_label.image = photo

            image_label = tk.Label(image_container, bg="#F2F4F7")
            image_label.pack(expand=True, fill="both")
            image_container.bind("<Configure>", resize_image)
        except FileNotFoundError:
            tk.Label(image_container, text="[ SecureGate Branding ]", font=("Segoe UI", 16, "italic"),
                     fg="#bdc3c7", bg="#F2F4F7").pack(expand=True)

    # ================= SETNUM 2: ADMIN LOG IN =================
    if setnum == 2:
        BG_COLOR, CARD_BG, ACCENT_DARK, PRIMARY_BLUE = (
            "#f4f7f6", "#ffffff", "#2c3e50", "#3498db"
        )

        sidebar.pack_forget()

        database = db()
        connection, cursor = database[0], database[1]
        cursor.execute("SELECT admin_name FROM settings")
        results = cursor.fetchall()

        if not results:
            settingshow(1)
            return

        login_center_frame = tk.Frame(content_frame, bg=BG_COLOR)
        login_center_frame.pack(expand=True, fill="both")

        # ---------- Shadow ----------
        shadow = tk.Frame(login_center_frame, bg="#dfe4ea")
        shadow.place(relx=0.5, rely=0.5, anchor="center", width=420, height=460)

        # ---------- Login Card ----------
        login_card = tk.Frame(
            login_center_frame,
            bg=CARD_BG,
            padx=45,
            pady=45,
            highlightthickness=1,
            highlightbackground="#dcdde1"
        )
        login_card.place(relx=0.5, rely=0.5, anchor="center")

        # ---------- Branding ----------
        tk.Label(
            login_card,
            text="SecureGate",
            font=("Segoe UI Variable Display", 26, "bold"),
            fg=ACCENT_DARK,
            bg=CARD_BG
        ).pack(pady=(0, 4))

        tk.Label(
            login_card,
            text="Administrator Access Portal",
            font=("Segoe UI", 10),
            fg="#7f8c8d",
            bg=CARD_BG
        ).pack(pady=(0, 20))

        # ---------- Inputs ----------
        admin_user = create_login_field(
            login_card, "Username", fg=ACCENT_DARK, bg=CARD_BG
        )
        admin_pass = create_login_field(
            login_card, "Password", is_password=True, fg=ACCENT_DARK, bg=CARD_BG
        )

        # ---------- Forgot Password (NOW PERFECTLY PLACED) ----------
        forgot_btn = tk.Label(
            login_card,
            text="Forgot password?",
            fg="#7f8c8d",
            bg=CARD_BG,
            font=("Segoe UI", 9),
            cursor="hand2"
        )
        forgot_btn.pack(anchor="e", pady=(0, 16))

        forgot_btn.bind("<Enter>", lambda e: forgot_btn.config(fg=PRIMARY_BLUE))
        forgot_btn.bind("<Leave>", lambda e: forgot_btn.config(fg="#7f8c8d"))
        forgot_btn.bind("<Button-1>", lambda e: forgot_password())

        # ---------- Login Button ----------
        submit_button = tk.Button(
            login_card,
            text="AUTHORIZE ACCESS",
            font=("Segoe UI", 10, "bold"),
            bg=PRIMARY_BLUE,
            fg="white",
            relief="flat",
            cursor="hand2",
            pady=11,
            activebackground="#2980b9",
            command=lambda: validate(admin_user.get(), admin_pass.get())
        )
        submit_button.pack(fill="x", pady=(18, 12))

        # ---------- Footer ----------
        tk.Label(
            login_card,
            text="SecureGate © Network Defense System",
            font=("Segoe UI", 8),
            fg="#b2bec3",
            bg=CARD_BG
        ).pack(pady=(12, 0))

    # ================= SETNUM 3: MAIN CONFIGURATION =================
    if setnum == 3:
        # ================== COLOR SYSTEM ==================
        BG_COLOR = "#f5f7fb"
        CARD_BG = "#ffffff"
        ACCENT_BLUE = "#2563eb"
        ACCENT_BLUE_DARK = "#1e40af"
        HOVER_GRAY = "#f1f5f9"
        TEXT_MAIN = "#0f172a"
        TEXT_SUB = "#64748b"
        BORDER_LIGHT = "#e5e7eb"

        # ================== STYLE CONFIG ==================
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "TLabelFrame",
            background=BG_COLOR,
            borderwidth=0,
            relief="flat"
        )

        style.configure(
            "TLabelFrame.Label",
            font=("Segoe UI Variable", 14, "bold"),
            foreground=TEXT_MAIN,
            background=BG_COLOR
        )

        style.configure(
            "TEntry",
            padding=(10, 8)
        )

        style.configure(
            "TCombobox",
            padding=6
        )

        # ================== MAIN CONTAINER ==================
        main_view = tk.Frame(content_frame, bg=BG_COLOR)
        main_view.pack(fill="both", expand=True)

        # ================== HEADER ==================
        header_frame = tk.Frame(main_view, bg=BG_COLOR)
        header_frame.pack(fill="x", padx=60, pady=(35, 15))

        tk.Label(
            header_frame,
            text="System Configuration",
            font=("Segoe UI Variable Display", 26, "bold"),
            bg=BG_COLOR,
            fg=TEXT_MAIN
        ).pack(anchor="w")

        tk.Label(
            header_frame,
            text="Manage network security, limits, and notification behavior",
            font=("Segoe UI", 10),
            bg=BG_COLOR,
            fg=TEXT_SUB
        ).pack(anchor="w", pady=(6, 0))

        # ================== SETTINGS WRAPPER ==================
        settings_container = tk.Frame(main_view, bg=BG_COLOR)
        settings_container.pack(fill="both", expand=True, padx=60, pady=10)

        # ================== ROW BUILDER ==================
        def add_setting_row(parent, row, label_text, widget_type="entry", cmd=None, var=None):
            row_frame = tk.Frame(parent, bg=CARD_BG, highlightbackground=BORDER_LIGHT,
                                highlightthickness=1)
            row_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=6)
            row_frame.columnconfigure(1, weight=1)

            tk.Label(
                row_frame,
                text=label_text,
                font=("Segoe UI Semibold", 10),
                bg=CARD_BG,
                fg=TEXT_SUB,
                width=26,
                anchor="w"
            ).grid(row=0, column=0, padx=(22, 10), pady=18)

            if widget_type == "entry":
                ent = ttk.Entry(row_frame)
                ent.grid(row=0, column=1, sticky="ew", padx=10)

                if cmd:
                    btn = tk.Button(
                        row_frame,
                        text="UPDATE",
                        command=cmd,
                        bg=CARD_BG,
                        fg=ACCENT_BLUE,
                        relief="flat",
                        font=("Segoe UI", 9, "bold"),
                        padx=16,
                        pady=4,
                        cursor="hand2",
                        activebackground=HOVER_GRAY,
                        highlightbackground=BORDER_LIGHT
                    )
                    btn.grid(row=0, column=2, padx=(10, 22))
                return ent

            elif widget_type == "check":
                cb_frame = tk.Frame(row_frame, bg=CARD_BG)
                cb_frame.grid(row=0, column=1, sticky="w", padx=10)

                cb = ttk.Checkbutton(cb_frame, variable=var)
                cb.pack(side="left")

                if cmd:
                    btn = tk.Button(
                        row_frame,
                        text="UPDATE",
                        command=cmd,
                        bg=CARD_BG,
                        fg=ACCENT_BLUE,
                        relief="flat",
                        font=("Segoe UI", 9, "bold"),
                        padx=16,
                        pady=4,
                        cursor="hand2"
                    )
                    btn.grid(row=0, column=2, padx=(10, 22))
                return cb

        # ================== GENERAL SETTINGS ==================
        general_card = ttk.LabelFrame(settings_container, text=" General Settings ")
        general_card.pack(fill="x", pady=18)

        phone = add_setting_row(general_card, 0, "Emergency Contact",
                                cmd=lambda: update_setting("phone"))

        new_email = add_setting_row(general_card, 1, "System Alert Email",
                                    cmd=lambda: update_setting("new email"))

        email_notify_var = tk.BooleanVar()
        add_setting_row(
            general_card, 2,
            "Real-time Notifications",
            "check",
            lambda: update_setting("email_notifications"),
            email_notify_var
        )

        # ================== TRAFFIC CONTROLS ==================
        limit_card = ttk.LabelFrame(settings_container, text=" Traffic Controls ")
        limit_card.pack(fill="x", pady=18)

        rules_row = tk.Frame(limit_card, bg=CARD_BG,
                            highlightbackground=BORDER_LIGHT,
                            highlightthickness=1)
        rules_row.grid(row=0, column=0, columnspan=3, sticky="ew", pady=6)

        tk.Label(
            rules_row,
            text="Traffic Rules Engine",
            font=("Segoe UI Semibold", 10),
            bg=CARD_BG,
            fg=TEXT_SUB,
            width=26,
            anchor="w"
        ).pack(side="left", padx=(22, 10), pady=18)

        ctrl_grp = tk.Frame(rules_row, bg=CARD_BG)
        ctrl_grp.pack(side="left", fill="x", expand=True)

        tk.Label(ctrl_grp, text="Interval",
                bg=CARD_BG, fg=TEXT_SUB,
                font=("Segoe UI", 9)).pack(side="left", padx=6)

        interval_var = tk.StringVar()
        ttk.Combobox(
            ctrl_grp,
            textvariable=interval_var,
            values=[1, 5, 10, 30, 60],
            width=8,
            state="readonly"
        ).pack(side="left", padx=6)

        tk.Label(ctrl_grp, text="Requests",
                bg=CARD_BG, fg=TEXT_SUB,
                font=("Segoe UI", 9)).pack(side="left", padx=(16, 6))

        request_limit_var = tk.StringVar()
        ttk.Combobox(
            ctrl_grp,
            textvariable=request_limit_var,
            values=[10, 50, 100, 500, 1000],
            width=8,
            state="readonly"
        ).pack(side="left", padx=6)

        tk.Button(
            rules_row,
            text="APPLY POLICY",
            bg=ACCENT_BLUE,
            fg="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=24,
            pady=6,
            cursor="hand2",
            activebackground=ACCENT_BLUE_DARK,
            command=lambda: update_setting("max_requests_per_ip")
        ).pack(side="right", padx=24)

        max_requests_per_ip = add_setting_row(
            limit_card, 1,
            "Max Global Requests/IP",
            cmd=lambda: update_setting("max_requests_per_ip")
        )

        # ================== NETWORK INTELLIGENCE ==================
        security_card = ttk.LabelFrame(settings_container, text=" Network Intelligence ")
        security_card.pack(fill="x", pady=18)

        honeypot_ips = add_setting_row(
            security_card, 0,
            "Honeypot IP Range",
            cmd=lambda: update_setting("honeypot_ips")
        )

        folder_path = add_setting_row(
            security_card, 1,
            "Protected Directory",
            cmd=lambda: update_setting("sensitive folder")
        )

        whitelist = add_setting_row(
            security_card, 2,
            "Permitted IP List",
            cmd=lambda: update_setting("whitelist")
        )

        blacklist = add_setting_row(
            security_card, 3,
            "Restricted IP List",
            cmd=lambda: update_setting("blacklist")
        )

        # ================== LOAD LOGIC (UNCHANGED) ==================
        data = fetch_settings_data()
        if data:
            fields = [phone, new_email, None, None, honeypot_ips,
                    None, folder_path, whitelist, blacklist]

            for i, field in enumerate(fields):
                if field and i < len(data) and data[i]:
                    field.delete(0, 'end')
                    field.insert(0, str(data[i]))

            if data[2]:
                interval_var.set(data[2])

            if data[9] is not None:
                email_notify_var.set(bool(data[9]))

def fetch_settings_data():
    try:
        conn, cursor = db()
        cursor.execute("""
            SELECT
                phone,
                email,
                request_time_limit,
                max_requests_per_ip,
                honeypot_ips,
                allowed_ports,
                sensitive_folders,
                whitelisted_ips,
                blacklisted_ips,
                email_alerts_enabled
            FROM settings
            LIMIT 1
        """)
        data = cursor.fetchone()
        cursor.close()
        conn.close()
        return data
    except Exception as e:
        print("fetch_settings_data error:", e)
        return None
# ================= LOGIN FIELD HELPER =================
OTP_DATA = {"otp": None}
import sys
import random
import bcrypt

from securegate_new import EMERGENCY_ALERT
def forgot_password():
    win = tk.Toplevel(root)
    win.title("Forgot Password")
    win.geometry("400x330")
    win.resizable(False, False)
    win.transient(root)
    win.grab_set()

    frame = tk.Frame(win, padx=30, pady=20)
    frame.pack(fill="both", expand=True)

    tk.Label(
        frame,
        text="Password Recovery",
        font=("Segoe UI", 14, "bold")
    ).pack(pady=(0, 10))

    info_lbl = tk.Label(
        frame,
        text="OTP will be sent to your registered email",
        font=("Segoe UI", 9),
        fg="#7f8c8d"
    )
    info_lbl.pack(anchor="w")

    entry = ttk.Entry(frame)
    entry.pack(fill="x", pady=8)

    action_btn = tk.Button(
        frame,
        text="SEND OTP",
        bg="#3498db",
        fg="white",
        relief="flat",
        cursor="hand2"
    )
    action_btn.pack(fill="x", pady=10)

    step = {"value": 1}

    def process():
        conn, cursor = db()

        # ---------- STEP 1: SEND OTP ----------
        if step["value"] == 1:
            cursor.execute("SELECT email FROM settings WHERE id = 1")
            row = cursor.fetchone()

            if not row or not row[0]:
                messagebox.showerror(
                    "Critical Error",
                    "Registered admin email not found.\nApplication will close."
                )
                sys.exit()

            otp = str(random.randint(100000, 999999))
            OTP_DATA["otp"] = otp

            try:
                EMERGENCY_ALERT.send_email_alert(
                    subject="SecureGate Password Reset OTP",
                    message=f"""
Your SecureGate OTP is:

<b>{otp}</b>

Do not share this OTP with anyone.
If you did not request a password reset, please contact admin immediately.
                    """
                )
            except Exception:
                messagebox.showerror(
                    "Email Error",
                    "Failed to send OTP.\nApplication will close."
                )
                sys.exit()

            info_lbl.config(
                text="OTP has been sent to your registered email.\nPlease verify."
            )
            entry.delete(0, "end")
            action_btn.config(text="VERIFY OTP")
            step["value"] = 2

        # ---------- STEP 2: VERIFY OTP ----------
        elif step["value"] == 2:
            if entry.get().strip() != OTP_DATA["otp"]:
                messagebox.showerror(
                    "Invalid OTP",
                    "OTP verification failed.\nApplication will close."
                )
                sys.exit()

            info_lbl.config(text="Set new password")
            entry.destroy()

            pwd1 = ttk.Entry(frame, show="*")
            pwd1.pack(fill="x", pady=6)

            pwd2 = ttk.Entry(frame, show="*")
            pwd2.pack(fill="x", pady=6)

            action_btn.config(text="RESET PASSWORD")
            step["pwd1"] = pwd1
            step["pwd2"] = pwd2
            step["value"] = 3

        # ---------- STEP 3: RESET PASSWORD ----------
        else:
            pwd1 = step["pwd1"].get()
            pwd2 = step["pwd2"].get()

            if pwd1 != pwd2 or len(pwd1) < 8:
                messagebox.showerror(
                    "Invalid Password",
                    "Passwords must match and be at least 8 characters."
                )
                return

            hashed = bcrypt.hashpw(
                pwd1.encode(), bcrypt.gensalt()
            ).decode()

            cursor.execute(
                "UPDATE settings SET password_hash=%s WHERE id=1",
                (hashed,)
            )
            conn.commit()

            OTP_DATA["otp"] = None
            messagebox.showinfo(
                "Success",
                "Password updated successfully.\nApplication will now close."
            )
            sys.exit()

    action_btn.config(command=process)




def create_login_field(parent, label_text, is_password=False, fg="#2c3e50", bg="#ffffff"):
    tk.Label(
        parent,
        text=label_text,
        font=("Segoe UI", 10, "bold"),
        fg=fg,
        bg=bg
    ).pack(anchor="w", pady=(10, 0))

    entry = ttk.Entry(
        parent,
        width=36,
        font=("Segoe UI", 11),
        show="•" if is_password else ""
    )
    entry.pack(fill="x", pady=(6, 14), ipady=5)
    return entry


def update_setting(val):
    global admin_user, email, form_container, admin_pass, phone, time_limit
    global honeypot_ips, folder_path, allowed_ports, port_services
    global whitelist, blacklist, interval_var, request_limit_var
    global port, service, email_notify_var, new_email, max_requests_per_ip

    # ---------- REGEX PATTERNS ----------
    USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")
    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    PHONE_REGEX = re.compile(r"^[6-9]\d{9}$")
    PASSWORD_REGEX = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$"
    )
    PORTS_REGEX = re.compile(r"^(\d{1,5})(,\d{1,5})*$")
    PATH_REGEX = re.compile(r"^[a-zA-Z0-9_\/\\\:\.-]+$")

    IPV4_REGEX = re.compile(
        r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    IPV6_REGEX = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")

    dt = db()
    connection = dt[0]
    cursor = dt[1]

    # ================= ADMIN SIGN-UP =================
    if val == "sign in":
        a = custom_askyesno("Admin Registration", "Do you want to confirm it")
        if not a:
            return

        admin = admin_user.get().strip()
        em = email.get().strip()
        pwd = admin_pass.get()

        if not USERNAME_REGEX.match(admin):
            messagebox.showerror("Invalid Username",
                                 "Username must be 3–30 chars (letters, numbers, _, ., -)")
            return

        if not EMAIL_REGEX.match(em):
            messagebox.showerror("Invalid Email", "Enter a valid email address.")
            return

        if not PASSWORD_REGEX.match(pwd):
            messagebox.showerror(
                "Weak Password",
                "Password must contain:\n• 8+ chars\n• Uppercase\n• Lowercase\n• Number\n• Special character"
            )
            return

        pass_hs = hash_password(pwd)
        cursor.execute(
            "INSERT INTO settings (admin_name,email,password_hash) VALUES (%s,%s,%s)",
            (admin, em, pass_hs)
        )
        connection.commit()

        dashboardshow()
        if form_container:
            form_container.destroy()
        if image_container:
            image_container.destroy()

        validate_user = True
        return

    # ================= PHONE =================
    if val == "phone":
        phone_val = phone.get().strip()
        if not PHONE_REGEX.match(phone_val):
            messagebox.showerror("Invalid Phone", "Enter a valid 10-digit mobile number.")
            return

        cursor.execute("UPDATE settings SET phone = %s", (phone_val,))
        connection.commit()
        return

    # ================= EMAIL =================
    if val == "new email":
        email_val = new_email.get().strip()
        if not EMAIL_REGEX.match(email_val):
            messagebox.showerror("Invalid Email", "Enter a valid email address.")
            return

        cursor.execute("UPDATE settings SET email = %s", (email_val,))
        connection.commit()
        return

    # ================= RATE LIMIT =================
    if val == "max_requests_per_ip":
        interval = interval_var.get()
        limit = request_limit_var.get()

        if not interval.isdigit() or not limit.isdigit():
            messagebox.showerror("Invalid Input", "Interval and limit must be numbers.")
            return

        jsonins("rqpt", interval, limit)
        return

    # ================= HONEYPOT =================
    if val == "honeypot_ips":
        ip_val = honeypot_ips.get().strip()
        if not (IPV4_REGEX.match(ip_val) or IPV6_REGEX.match(ip_val)):
            messagebox.showerror("Invalid IP", "Enter valid IPv4 or IPv6 address.")
            return

        ins_honey(ip_val)
        return

    # ================= SENSITIVE FOLDER =================
    if val == "sensitive folder":
        path = folder_path.get().strip()
        if not PATH_REGEX.match(path):
            messagebox.showerror("Invalid Path", "Invalid folder path.")
            return

        cursor.execute("UPDATE settings SET sensitive_folders = %s", (path,))
        connection.commit()
        return

    # ================= ALLOWED PORTS =================
    if val == "allowed_port":
        ports_raw = allowed_ports.get().strip()
        if not PORTS_REGEX.match(ports_raw):
            messagebox.showerror("Invalid Ports", "Use format: 80,443,22")
            return

        ports = []
        for p in ports_raw.split(","):
            p = int(p)
            if not (1 <= p <= 65535):
                messagebox.showerror("Invalid Port", f"Port {p} out of range.")
                return
            ports.append(p)

        cursor.execute(
            "UPDATE settings SET allowed_ports = %s",
            (json.dumps(ports),)
        )
        connection.commit()
        messagebox.showinfo("Success", "Allowed ports updated.")
        return

    # ================= EMAIL NOTIFICATION =================
    if val == "email_notifications":
        cursor.execute(
            "UPDATE settings SET email_alerts_enabled = %s",
            (email_notify_var.get(),)
        )
        connection.commit()
        return

    # ================= WHITELIST / BLACKLIST =================
    if val in ["whitelist", "blacklist"]:
        ip_value = (whitelist.get() if val == "whitelist" else blacklist.get()).strip()

        if not (IPV4_REGEX.match(ip_value) or IPV6_REGEX.match(ip_value)):
            messagebox.showerror("Invalid IP", "Enter valid IPv4 or IPv6.")
            return

        IPS_ob = IPS
        all_whitelist = IPS_ob.whitelist_ip("all")
        all_blacklist = IPS_ob.blacklist_ip("all")

        if ip_value in all_whitelist or ip_value in all_blacklist:
            messagebox.showerror("Duplicate", "IP already exists.")
            return

        if val == "whitelist":
            IPS_ob.whitelist_ip("add", ip_value)
            messagebox.showinfo("Success", "IP added to Whitelist.")
        else:
            IPS_ob.blacklist_ip("add", ip_value)
            messagebox.showinfo("Success", "IP added to Blacklist.")




def dashboardshow():
    sidebar.pack(side="left", fill="y")
    global connection, cursor

    # Clear existing widgets
    for widget in content_frame.winfo_children():
        widget.destroy()

    # --- UI THEME COLORS ---
    BG_MAIN = "#f4f7f6"
    ACCENT_COLOR = "#2c3e50"
    ALERT_RED = "#e74c3c"
    CARD_BG = "#ffffff"
    ACCENT_BLUE = "#3498db"
    
    content_frame.configure(bg=BG_MAIN)

    # ---------------- 1. HEADER SECTION ----------------
    header_frame = tk.Frame(content_frame, bg=BG_MAIN)
    header_frame.pack(fill="x", padx=30, pady=(20, 10))

    tk.Label(
        header_frame,
        text="Security Command Center",
        font=("Segoe UI", 24, "bold"),
        fg=ACCENT_COLOR,
        bg=BG_MAIN
    ).pack(side="left")

    # ---------------- 2. CRITICAL ALERTS (TOP PRIORITY) ----------------
    # High-visibility container for active threats
    alerts_container = tk.LabelFrame(
        content_frame, 
        text=" 🚨 ACTIVE SECURITY THREATS ", 
        font=("Segoe UI", 11, "bold"),
        fg=ALERT_RED,
        bg=CARD_BG,
        padx=15,
        pady=15,
        relief="flat",
        highlightbackground="#dcdde1",
        highlightthickness=1
    )
    alerts_container.pack(fill="x", padx=30, pady=10)

    # Treeview Style for Alerts
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Alert.Treeview", rowheight=30, font=("Segoe UI", 9))
    style.configure("Alert.Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#fdf2f2")

    columns_alert = ("attack_type", "src_ip", "severity", "hit_count", "last_detected")
    alert_tree = ttk.Treeview(alerts_container, columns=columns_alert, show="headings", height=4, style="Alert.Treeview")
    
    alert_tree.heading("attack_type", text="Attack Type")
    alert_tree.heading("src_ip", text="Source IP")
    alert_tree.heading("severity", text="Severity")
    alert_tree.heading("hit_count", text="Hits")
    alert_tree.heading("last_detected", text="Last Detected")

    # Column Formatting
    alert_tree.column("severity", width=100, anchor="center")
    alert_tree.column("hit_count", width=80, anchor="center")

    # Severity Tags
    alert_tree.tag_configure("HIGH", background="#ffcccc", foreground="#900")
    alert_tree.tag_configure("MEDIUM", background="#ffe0b3")
    alert_tree.tag_configure("LOW", background="#d4edda")

    # Fetch and Insert Alert Data
    try:
        database = db()
        conn, cur = database[0], database[1]
        cur.execute("""
            SELECT attack_type, src_ip, severity, hit_count, last_detected 
            FROM attack_state WHERE is_active = 1 
            ORDER BY FIELD(severity, 'HIGH', 'MEDIUM', 'LOW'), last_detected DESC
        """)
        for row in cur.fetchall():
            alert_tree.insert("", "end", values=row, tags=(row[2],))
    except Exception as e:
        tk.Label(alerts_container, text=f"Update Error: {e}", bg=CARD_BG, fg="red").pack()

    alert_tree.pack(fill="x", expand=True)

    # ---------------- 3. ANALYTICS SECTION (VISUALS & LOGS) ----------------
    # A subtle title to separate the data
    tk.Label(
        content_frame, 
        text="Geographic Traffic Analysis", 
        font=("Segoe UI", 14, "bold"),
        fg=ACCENT_COLOR,
        bg=BG_MAIN
    ).pack(anchor="w", padx=30, pady=(20, 5))

    # We call the modified chart function and pass the content_frame
    show_bar_chart_by_country_integrated()

    # ---------------- LOGIC & THREADS ----------------
    thread = threading.Thread(target=update_null_countries)
    thread.daemon = True
    thread.start()

    global refresh_jobs
    job_id = root.after(SECUREGATE_GUI_REFRESH_INTERVAL * 1000, lambda: data_to_show("Dashboard"))
    refresh_jobs.append(job_id)

def show_bar_chart_by_country_integrated():
    # Colors for Chart
    BG_MAIN = "#f4f7f6"
    CARD_BG = "#ffffff"
    RED_CHART = "#e74c3c"
    GREEN_CHART = "#2ecc71"
    ACCENT_BLUE = "#3498db"

    blocked = fetch_ips("blocked") or []
    unblocked = fetch_ips("unblocked") or []

    # Data Processing
    blocked_counts = collections.defaultdict(int)
    for ip, country in blocked:
        name = str(country).strip() if country and str(country).strip() != "" else "Unknown"
        blocked_counts[name] += 1

    unblocked_counts = collections.defaultdict(int)
    for ip, country in unblocked:
        name = str(country).strip() if country and str(country).strip() != "" else "Unknown"
        unblocked_counts[name] += 1

    all_countries = sorted(list(set(blocked_counts.keys()) | set(unblocked_counts.keys())))

    if not all_countries:
        tk.Label(content_frame, text="No Data Available", bg=BG_MAIN).pack(pady=20)
        return

    # --- CHART CARD ---
    chart_card = tk.Frame(content_frame, bg="white", highlightbackground="#dcdde1", highlightthickness=1)
    chart_card.pack(fill="x", padx=30, pady=10)

    plt.style.use('ggplot')
    fig, ax = plt.subplots(figsize=(10, 4), dpi=100)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    width = 0.35
    x = range(len(all_countries))

    ax.bar(x, [blocked_counts.get(c, 0) for c in all_countries], width, 
           label='Blocked', color=RED_CHART, edgecolor='white', linewidth=0.5)
    ax.bar([i + width for i in x], [unblocked_counts.get(c, 0) for c in all_countries], width, 
           label='Unblocked', color=GREEN_CHART, edgecolor='white', linewidth=0.5)

    ax.set_ylabel('Total IPs', fontname='Segoe UI', fontweight='bold', alpha=0.6)
    ax.set_xticks([i + width / 2 for i in x])
    ax.set_xticklabels(all_countries, rotation=25, ha='right', fontsize=8)
    ax.legend(frameon=False)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, master=chart_card)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

    # --- DATA TABLE CARD ---
    table_frame = tk.Frame(content_frame, bg=BG_MAIN)
    table_frame.pack(fill='both', expand=True, padx=30, pady=(10, 20))

    # Table Style
    style = ttk.Style()
    style.configure("Table.Treeview", background=CARD_BG, rowheight=28, font=("Segoe UI", 9))
    style.configure("Table.Treeview.Heading", background="#ecf0f1", font=("Segoe UI", 10, "bold"))

    columns = ('country', 'blocked', 'unblocked')
    tree = ttk.Treeview(table_frame, columns=columns, show='headings', style="Table.Treeview")

    tree.heading('country', text='  COUNTRY')
    tree.column('country', anchor='w', width=200)
    tree.heading('blocked', text='  BLOCKED')
    tree.column('blocked', anchor='center', width=100)
    tree.heading('unblocked', text='  UNBLOCKED')
    tree.column('unblocked', anchor='center', width=100)

    for i, country in enumerate(all_countries):
        tag = 'even' if i % 2 == 0 else 'odd'
        tree.insert('', 'end', values=(f" {country}", blocked_counts.get(country, 0), unblocked_counts.get(country, 0)), tags=(tag,))

    tree.tag_configure('odd', background='#f9f9f9')
    tree.tag_configure('even', background='#ffffff')

    scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    tree.pack(side='left', fill='both', expand=True)

def connect_db():
    load_dotenv(ENV_FILE, override=True)

    return mysql.connector.connect(
        host=os.getenv("SECUREGATE_DB_HOST"),
        user=os.getenv("SECUREGATE_DB_USER"),
        password=os.getenv("SECUREGATE_DB_PASS"),
        database=os.getenv("SECUREGATE_DB_NAME"),
        port=int(os.getenv("SECUREGATE_DB_PORT", "3306")),
        autocommit=True
    )

def datamanage(page):
    # This now only returns the Table Name. 
    # Columns are handled automatically in the thread.
    mapping = {
        "IP Monitor": "ip",
        "Logs": "iprequest_junction",
        "Port Monitor": "request_type",
        "Protocol Monitor": "Network_protocol",
        "blocked IP": "ip" # We filter this in the query usually
    }
    return mapping.get(page, page)

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

def update_gui_with_data(fetched_rows, cols, page_name, reset_pagination=True):
    global all_rows, columns, APP_STATE
    
    if fetched_rows == "dashboard":
        APP_STATE["current_view"] = "dashboard"
        dashboardshow()
        return
    elif fetched_rows == "settings":
        APP_STATE["current_view"] = "settings"
        settingshow(3)
        return

    # Update Data
    all_rows = fetched_rows if fetched_rows is not None else []
    columns = cols
    
    # THE STATE FIX: Only reset to page 0 if it's a NEW click, not a refresh
    if reset_pagination:
        APP_STATE["current_page"] = 0
    
    APP_STATE["current_view"] = "data_logs"
    APP_STATE["last_page_name"] = page_name # Remember WHICH table we are on
    
    show_page_data()
    
    # Schedule next refresh
    if page_name != "Setting":
        clear_all_jobs() # Prevent timer stacking
        job_id = root.after(SECUREGATE_GUI_REFRESH_INTERVAL * 1000, lambda: data_to_show(page_name, False)) # False = Don't reset page
        refresh_jobs.append(job_id)

def data_to_show(page_name, reset_pagination=True):
    """Main function called by button clicks (True) and refresh (False)."""
    thread = threading.Thread(target=fetch_data_in_thread, args=(page_name, reset_pagination))
    thread.daemon = True
    thread.start()
def fetch_data_in_thread(page_name, reset_pagination):
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # 1. Map page names to actual DB table names
        table_mapping = {
            "IP Monitor": "ip",
            "Logs": "iprequest_junction",
            "Port Monitor": "request_type",
            "Protocol Monitor": "Network_protocol",
       }

        fetched_rows = None
        dynamic_cols = []

        if page_name == "Dashboard":
            fetched_rows = "dashboard"
        elif page_name == "Setting":
            fetched_rows = "settings"
        else:
            # Get the table name from our mapping
            db_table = table_mapping.get(page_name)
            
            if db_table:
                # 2. Execute a dynamic query
                cursor.execute(f"SELECT * FROM {db_table}")
                
                # 3. DYNAMICALLY EXTRACT COLUMN NAMES
                # cursor.description returns a tuple for each column; 
                # index 0 is always the column name.
                dynamic_cols = [desc[0].replace("_", " ").title() for desc in cursor.description]
                
                fetched_rows = cursor.fetchall()

        # Pass the dynamically discovered columns to the GUI
        root.after(0, lambda: update_gui_with_data(fetched_rows, dynamic_cols, page_name, reset_pagination))
        
        if conn.is_connected():
            cursor.close()
            conn.close()
            
    except Exception as e:
        print(f"Dynamic Fetch Error: {e}")





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
    



def change_page(delta):
    """Changes page while strictly preserving state."""
    APP_STATE["current_page"] += delta
    show_page_data() # Reloads with new page index

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
    if SECUREGATE_GUI_ICON and os.path.exists(SECUREGATE_GUI_ICON):
        root.iconbitmap(SECUREGATE_GUI_ICON)
except tk.TclError:
        print("Icon not found. Skipping.")

INITIAL_WIDTH = SECUREGATE_GUI_WIDTH
INITIAL_HEIGHT = SECUREGATE_GUI_HEIGHT

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


def on_enter(e):
    e.widget['background'] = "#4a6572" # Lighter slate

def on_leave(e):
    e.widget['background'] = "#34495e" # Original slate

for name in pages:
    btn = tk.Button(
        sidebar,
        text=f"  {name}", # Spacing for icon feel
        anchor="w",       # Align text to left
        fg="white",
        bg="#34495e",
        font=("Segoe UI", 11),
        relief="flat",
        padx=20,
        pady=10,
        activebackground="#1abc9c", # Turquoise accent on click
        activeforeground="white",
        command=partial(handle_button_click, name)
    )
    btn.pack(fill="x", pady=1)
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)


settingshow(2)
# Initialize these at the top of your script if not already done
current_page = 0
rows_per_page = SECUREGATE_GUI_ROWS_PER_PAGE


def show_page_data(preserve_state=True):
    """
    preserve_state: If True, stays on the current page. 
                    If False, resets to page 0 (useful for new searches).
    """
    global all_rows, columns, current_page, rows_per_page

    # --- UI THEME COLORS ---
    BG_MAIN = "#f4f7f6"
    CARD_BG = "#ffffff"
    ACCENT_BLUE = "#3498db"
    TEXT_COLOR = "#2c3e50"

    # 1. State Preservation Logic
    if not preserve_state:
        current_page = 0

    # Safety check: ensure current_page isn't out of bounds after a data change
    total_rows = len(all_rows)
    max_pages = max(0, (total_rows - 1) // rows_per_page)
    if current_page > max_pages:
        current_page = max_pages

    # Calculate pagination slice
    start = current_page * rows_per_page
    end = start + rows_per_page
    rows = all_rows[start:end]

    # Clear content_frame
    for widget in content_frame.winfo_children():
        widget.destroy()
    
    content_frame.configure(bg=BG_MAIN)

    # --- HEADER ---
    header_frame = tk.Frame(content_frame, bg=BG_MAIN)
    header_frame.pack(fill="x", padx=30, pady=(20, 10))
    
    tk.Label(
        header_frame, 
        text=f"Network Data Logs", 
        font=("Segoe UI", 18, "bold"),
        fg=TEXT_COLOR, bg=BG_MAIN
    ).pack(side="left")

    # --- TABLE CONTAINER ---
    table_container = tk.Frame(content_frame, bg=CARD_BG, highlightbackground="#dcdde1", highlightthickness=1)
    table_container.pack(fill="both", expand=True, padx=30, pady=10)

    # --- STYLE ---
    style = ttk.Style()
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
    style.configure("Treeview", rowheight=32, font=("Segoe UI", 10))

    if not rows:
        no_data_frame = tk.Frame(table_container, bg=CARD_BG)
        no_data_frame.pack(expand=True)
        tk.Label(no_data_frame, text="No Data Available", font=("Segoe UI", 12), fg="gray", bg=CARD_BG).pack()
    else:
        tree = ttk.Treeview(table_container, columns=columns, show='headings')
        for col in columns:
            tree.heading(col, text=f" {col.upper()}")
            tree.column(col, anchor="w", width=120)

        tree.tag_configure('oddrow', background='#f9f9f9')
        tree.tag_configure('evenrow', background='white')

        for row_index, row in enumerate(rows):
            processed_row = [cell if cell not in [None, 0, "None"] else '-' for cell in row]
            tag = 'evenrow' if row_index % 2 == 0 else 'oddrow'
            tree.insert('', 'end', values=processed_row, tags=(tag,))

        scrollbar = ttk.Scrollbar(table_container, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # --- PERSISTENT NAVIGATION BAR ---
    nav_bar = tk.Frame(content_frame, bg=BG_MAIN)
    nav_bar.pack(fill="x", side="bottom", padx=30, pady=20)

    def create_nav_btn(parent, text, cmd, side):
        btn = tk.Button(
            parent, text=text, command=cmd, 
            font=("Segoe UI", 9, "bold"), bg=CARD_BG, fg=ACCENT_BLUE,
            relief="flat", highlightbackground=ACCENT_BLUE, highlightthickness=1,
            padx=15, pady=5, cursor="hand2"
        )
        btn.pack(side=side, padx=5)
        return btn

    # Pagination buttons only show if applicable
    if end < total_rows:
        create_nav_btn(nav_bar, "Next Page →", next_page, "right")
    
    if current_page > 0:
        create_nav_btn(nav_bar, "← Previous Page", prev_page, "left")

    # The "State Indicator"
    current_range = f"{start + 1}-{min(end, total_rows)}" if total_rows > 0 else "0-0"
    tk.Label(
        nav_bar, 
        text=f"Page {current_page + 1}  |  Showing {current_range} of {total_rows}",
        font=("Segoe UI", 9), fg="#7f8c8d", bg=BG_MAIN
    ).pack(side="left", expand=True)

# ---------------------------------------------------------
# GLOBAL NAVIGATION FUNCTIONS (Maintain State)
# ---------------------------------------------------------
def next_page():
    global current_page
    current_page += 1
    show_page_data(preserve_state=True)

def prev_page():
    global current_page
    current_page -= 1
    show_page_data(preserve_state=True)


root.mainloop()





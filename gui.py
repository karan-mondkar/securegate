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
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
import ipaddress
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
from tkinter import filedialog
import socket




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

SECUREGATE_GUI_LOAD_RECORD = os.getenv(
"SECUREGATE_GUI_LOAD_RECORD","10000"
)








RUN_ENGINE=False
validate_user=False
SECUREGATE_NETWORK_MONITOR = None
current_page = 0
rows_per_page =  SECUREGATE_GUI_ROWS_PER_PAGE

import re

all_rows = []
columns = []
original_rows = []   # ✅ ADD THIS LINE
# The Global App State
APP_STATE = {
    "current_view": "dashboard", # Tracks which page the user is on
    "current_page": 0,           # Tracks pagination
    "rows_per_page": SECUREGATE_GUI_ROWS_PER_PAGE,
    "search_query": "",          # Tracks if user filtered data
    "last_data_type": "logs"     # Tracks if we were looking at blocked or unblocked
,
"filter_column": None,
    "filter_value": None
,
   "sort_column": None,
    "sort_reverse": False
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
        load_dotenv(ENV_FILE, override=True)

        conn = mysql.connector.connect(
            host=os.getenv("SECUREGATE_DB_HOST"),
            user=os.getenv("SECUREGATE_DB_USER"),
            password=os.getenv("SECUREGATE_DB_PASS"),
            database=os.getenv("SECUREGATE_DB_NAME"),
            port=int(os.getenv("SECUREGATE_DB_PORT", "3306")),
            autocommit=True
        )

        cursor = conn.cursor(buffered=True)   
        return conn, cursor

    except Exception as e:
        print("SQL Error:", e)
        return None, None

import mysql.connector


from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime
from tkinter import filedialog















def export_alerts_from_db():
   

    # ---------- FETCH DATA ----------
    conn, cursor = db()
    cursor.execute("""
        SELECT
            attack_type,
            src_ip,
            severity,
            hit_count,
            first_detected,
            last_detected
        FROM attack_state
        WHERE is_active = 1
        ORDER BY FIELD(severity,'HIGH','MEDIUM','LOW'), last_detected DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        messagebox.showwarning("No Data", "No active security threats found.")
        return

    # ---------- FILE ----------
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF Files", "*.pdf")],
        title="Save Security Alert Report"
    )
    if not file_path:
        return

    # ---------- DOCUMENT (LANDSCAPE) ----------
    doc = SimpleDocTemplate(
        file_path,
        pagesize=landscape(A4),
        rightMargin=20,
        leftMargin=20,
        topMargin=30,
        bottomMargin=20
    )

    styles = getSampleStyleSheet()

    cell_style = ParagraphStyle(
        "cell",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
        wordWrap="CJK"   # 🔥 CRITICAL
    )

    elements = []

    # ---------- TITLE ----------
    elements.append(Paragraph(
        "<b>SecureGate – Active Security Threat Report</b>",
        styles["Title"]
    ))

    elements.append(Paragraph(
        f"Generated on: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        styles["Normal"]
    ))

    elements.append(Paragraph("<br/>", styles["Normal"]))

    # ---------- TABLE DATA ----------
    table_data = [[
        "Attack Type",
        "Source IP",
        "Severity",
        "Hits",
        "First Detected",
        "Last Detected"
    ]]

    for r in rows:
        table_data.append([
            Paragraph(str(r[0]), cell_style),
            Paragraph(str(r[1]), cell_style),
            Paragraph(str(r[2]), cell_style),
            Paragraph(str(r[3]), cell_style),
            Paragraph(r[4].strftime("%Y-%m-%d %H:%M:%S"), cell_style),
            Paragraph(r[5].strftime("%Y-%m-%d %H:%M:%S"), cell_style),
        ])

    # ---------- TABLE (FIXED WIDTHS) ----------
    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[
            90,    # Attack Type
            230,   # Source IP (IPv6 safe)
            80,    # Severity
            50,    # Hits
            130,   # First Detected
            130    # Last Detected
        ]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

        ("GRID", (0, 0), (-1, -1), 0.6, colors.grey),

        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 1), (3, -1), "CENTER"),

        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),

        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
    ]))

    elements.append(table)

    # ---------- BUILD ----------
    doc.build(elements)

    messagebox.showinfo(
        "Export Successful",
        f"Security alert report exported successfully:\n{file_path}"
    )
import bcrypt
from tkinter import messagebox




def fetch_country_request_stats():
    try:
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("""
           SELECT 
    country,
    SUM(request_count) AS total_requests
FROM ip
WHERE country IS NOT NULL
GROUP BY country
ORDER BY total_requests DESC
LIMIT 15;
        """)

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return rows

    except Exception as e:
        print("Country stats error:", e)
        return []

def show_country_heat_chart(parent):
    import numpy as np
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    data = fetch_country_request_stats()

    if not data:
        tk.Label(parent, text="No Country Data", bg="#f4f7f6").pack()
        return

    countries = []
    counts = []

    for country, total in data:
        countries.append(country if country else "Unknown")
        counts.append(float(total))

    if not counts:
        return

    # 🔥 Limit to Top 10 max
    countries = countries[:10]
    counts = counts[:10]

    total_all = sum(counts)
    max_val = max(counts)

    # 🔥 Dynamic height (very important)
    dynamic_height = 0.6 * len(countries)
    fig_height = max(4, dynamic_height)

    fig, ax = plt.subplots(figsize=(9, fig_height), dpi=110)

    y_positions = np.arange(len(countries))

    # Gradient coloring
    norm = plt.Normalize(min(counts), max_val)
    colors = plt.cm.Reds(norm(counts))

    bars = ax.barh(
        y_positions,
        counts,
        height=0.55,
        color=colors,
        edgecolor="black",
        linewidth=0.5
    )

    ax.set_yticks(y_positions)
    ax.set_yticklabels(countries, fontsize=9)

    # 🔥 Clean value labels (no overlap)
    for i, bar in enumerate(bars):
        width = bar.get_width()
        percent = (width / total_all) * 100

        ax.text(
            width + (max_val * 0.01),
            bar.get_y() + bar.get_height() / 2,
            f"{int(width)} ({percent:.1f}%)",
            va="center",
            fontsize=8
        )

    ax.set_xlim(0, max_val * 1.15)

    ax.set_xlabel("Total Requests", fontsize=10, fontweight="bold")
    ax.set_title(
        "Top Attacking Countries – Threat Intelligence Overview",
        fontsize=12,
        fontweight="bold",
        pad=15
    )

    ax.invert_yaxis()

    # Clean style
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.grid(axis="x", linestyle="--", alpha=0.25)

    fig.tight_layout()

    # Embed in Tkinter
    chart_card = tk.Frame(
        parent,
        bg="white",
        highlightbackground="#dcdde1",
        highlightthickness=1
    )
    chart_card.pack(fill="x", padx=30, pady=10)

    canvas = FigureCanvasTkAgg(fig, master=chart_card)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)




def validate(username, password):
    global validate_user

    conn, cursor = db()
    if not conn or not cursor:
        messagebox.showerror("DB Error", "Database connection failed")
        return

    try:
        cursor.execute(
            "SELECT password_hash FROM settings WHERE admin_name = %s LIMIT 1",
            (username,)
        )
        row = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    # ❌ Username not found
    if not row:
        messagebox.showerror("Login Failed", "Invalid username")
        return

    stored_hash = row[0]

    # DB may return string → convert to bytes
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")

    # ✅ bcrypt verification (THIS IS THE KEY FIX)
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        messagebox.showerror("Login Failed", "Invalid password")
        return

    # ✅ SUCCESS
    validate_user = True
    dashboardshow()





def decrypt_sensitive_file():
    try:
        conn, cursor = db()

        if not conn or not cursor:
            print("[DECRYPT ERROR] DB connection failed.")
            return False
        
        
        cursor.execute(
            "SELECT sensitive_folders FROM settings LIMIT 1"
        )
        result = cursor.fetchone()

        if not result or not result[0]:
            print("[DECRYPT] No sensitive file path configured.")
            return False

        sensitive_file = result[0].strip()

        encrypted_path = sensitive_file + ".enc"

        # -------- Check if encrypted file exists --------
        if not os.path.exists(encrypted_path):
            print("[DECRYPT] No encrypted file found to decrypt.")
            return False

        # -------- Check if already decrypted --------
        if os.path.exists(sensitive_file):
            print("[DECRYPT] File already exists in decrypted form.")
            return False

        # -------- Load key --------
        key_file = "securegate.key"

        if not os.path.exists(key_file):
            print("[DECRYPT ERROR] Encryption key not found.")
            return False

        from cryptography.fernet import Fernet

        with open(key_file, "rb") as kf:
            key = kf.read()

        fernet = Fernet(key)

        # -------- Decrypt --------
        with open(encrypted_path, "rb") as ef:
            encrypted_data = ef.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(sensitive_file, "wb") as df:
            df.write(decrypted_data)

        print(f"[DECRYPT SUCCESS] File restored: {sensitive_file}")

        return True

    except Exception as e:
        log_error("Decryption failed", e)
        print("[DECRYPT ERROR]", e)
        return False

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
global admin_user, email, admin_pass, time_limit, honeypot_ips,max_requests_per_minute,folder_path, allowed_ports, port_services,form_container,image_container,whitelist,blacklist,email_notify_var
global interval_var, request_limit_var


def fetch_settings_data():
    try:
        conn, cursor = db()
        cursor.execute("""
            SELECT
                email,
                email_token,
                suspicious_activity_alert_mail,
                email_alerts_enabled,
                max_requests_per_minute,
                honeypot_ips,
                sensitive_folders,
                remote_upload_directory,
                whitelisted_ips,
                blacklisted_ips
            FROM settings
            LIMIT 1
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row
    except Exception as e:
        print("fetch_settings_data error:", e)
        return None



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
        cursor.execute("SELECT max_requests_per_minute FROM settings limit 1")
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
            cursor.execute("UPDATE settings SET max_requests_per_minute = %s limit 1", (updated_json,))
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

def manage_traffic_rules(action, listbox=None):
    conn, cursor = db()

    # ---------- LOAD RULES ----------
    if action == "load":
        if not listbox:
            return

        listbox.delete(0, tk.END)
        cursor.execute("SELECT max_requests_per_minute FROM settings")
        row = cursor.fetchone()

        if row and row[0]:
            raw = row[0]

            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")

            try:
                rules = json.loads(raw)   # {"1": "10", "5": "100"}
            except Exception:
                rules = {}

            for interval, limit in rules.items():
                listbox.insert(tk.END, f"{interval} min → {limit} requests")

    # ---------- DELETE RULE ----------
    elif action == "delete":
        if not listbox or not listbox.curselection():
            messagebox.showwarning("No Selection", "Please select a rule to delete.")
            conn.close()
            return

        selected = listbox.get(listbox.curselection()[0])

        interval = selected.split(" min")[0]

        cursor.execute("SELECT max_requests_per_minute FROM settings")
        row = cursor.fetchone()

        if row and row[0]:
            raw = row[0]
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")

            rules = json.loads(raw)

            # Remove selected rule
            if interval in rules:
                del rules[interval]

            # Save back
            cursor.execute(
                "UPDATE settings SET max_requests_per_minute=%s",
                (json.dumps(rules),)
            )
            conn.commit()

        # Reload list
        listbox.delete(0, tk.END)
        for k, v in rules.items():
            listbox.insert(tk.END, f"{k} min → {v} requests")

    cursor.close()
    conn.close()


def attach_info(widget, text):
    tooltip = tk.Toplevel(widget)
    tooltip.withdraw()
    tooltip.overrideredirect(True)
    tooltip.configure(bg="#1f2937")

    label = tk.Label(
        tooltip,
        text=text,
        bg="#1f2937",
        fg="white",
        font=("Segoe UI", 9),
        wraplength=260,
        justify="left",
        padx=10,
        pady=6
    )
    label.pack()

    def show(event):
        x = event.widget.winfo_rootx() + 20
        y = event.widget.winfo_rooty() + 20
        tooltip.geometry(f"+{x}+{y}")
        tooltip.deiconify()

    def hide(event):
        tooltip.withdraw()

    widget.bind("<Enter>", show)
    widget.bind("<Leave>", hide)




IPV4_REGEX = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$")
IPV6_REGEX = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def handle_network_setting(mode, field, widget=None):
    """
    mode   : 'show' | 'update'
    field  : whitelisted_ips | blacklisted_ips | honeypot_ips
             sensitive_folders | remote_upload_directory
    """

    conn, cursor = db()
    if not conn or not cursor:
        messagebox.showerror("Database Error", "Unable to connect to database.")
        return

    # ================= SHOW MODE =================
    if mode == "show":
        cursor.execute(f"SELECT {field} FROM settings LIMIT 1")
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row[0] if row and row[0] else ""

    # ================= UPDATE MODE =================
    raw_value = widget.get().strip()

    # ============================================================
    # PATH-BASED SETTINGS VALIDATION (ENTERPRISE LEVEL)
    # ============================================================
    if field in ("sensitive_folders", "remote_upload_directory"):

        if not raw_value:
            messagebox.showerror("Invalid Input", "Path cannot be empty.")
            return

        # Must exist
        if not os.path.exists(raw_value):
            messagebox.showerror("Invalid Path", "Directory does not exist.")
            return

        # Must be directory
        if not os.path.isdir(raw_value):
            messagebox.showerror("Invalid Path", "Path must be a directory.")
            return

        # Must have read & write permission
        if not os.access(raw_value, os.R_OK | os.W_OK):
            messagebox.showerror(
                "Permission Error",
                "Application does not have read/write permission for this directory."
            )
            return

        # Prevent protecting system critical directories
        critical_paths = [
            "/", "/etc", "/bin", "/usr",
            "C:\\Windows", "C:\\Program Files"
        ]

        normalized_path = os.path.abspath(raw_value)

        for critical in critical_paths:
            if normalized_path.lower() == os.path.abspath(critical).lower():
                messagebox.showerror(
                    "Unsafe Directory",
                    "Cannot use system-critical directory."
                )
                return

        # Save if changed
        cursor.execute(f"SELECT {field} FROM settings LIMIT 1")
        current = cursor.fetchone()
        current_val = current[0] if current else None

        if raw_value == current_val:
            messagebox.showinfo("No Change", "This value is already set.")
            cursor.close()
            conn.close()
            return

        cursor.execute(
            f"UPDATE settings SET {field} = %s",
            (raw_value,)
        )
        conn.commit()
        cursor.close()
        conn.close()

        messagebox.showinfo(
            "Success",
            f"{field.replace('_', ' ').title()} updated successfully."
        )
        return

    # ============================================================
    # IP-BASED SETTINGS VALIDATION (WHITELIST / BLACKLIST / HONEYPOT)
    # ============================================================

    input_values = [ip.strip() for ip in raw_value.split(",") if ip.strip()]

    if not raw_value:
        # Allow empty configuration (user intentionally disables feature)
        cursor.execute(f"UPDATE settings SET {field} = NULL")
        conn.commit()
        cursor.close()
        conn.close()

        messagebox.showinfo(
            "Feature Disabled",
            f"{field.replace('_',' ').title()} has been cleared."
        )
        return

    validated_entries = []
    invalid_entries = []

    for value in input_values:
        try:
            # Allow IP or CIDR
            network = ipaddress.ip_network(value, strict=False)
            entry_str = str(network)

            # Remove /32 automatically
            if entry_str.endswith("/32"):
                entry_str = entry_str[:-3]

            validated_entries.append(entry_str)
        except ValueError:
            invalid_entries.append(value)

    if invalid_entries:
        messagebox.showerror(
            "Invalid IP(s)",
            "The following entries are invalid:\n\n" + "\n".join(invalid_entries)
        )
        return

    # Remove duplicates
    new_entries = list(dict.fromkeys(validated_entries))

    # ============================================================
    # HONEYPOT EXTRA SECURITY CHECKS
    # ============================================================
    if field == "honeypot_ips":
        for entry in new_entries:
            ip_obj = ipaddress.ip_network(entry, strict=False)

            if ip_obj.is_loopback:
                messagebox.showerror(
                    "Invalid Honeypot IP",
                    "Loopback addresses (127.0.0.1) are not allowed."
                )
                return

            if ip_obj.is_multicast:
                messagebox.showerror(
                    "Invalid Honeypot IP",
                    "Multicast addresses are not allowed."
                )
                return

            if ip_obj.prefixlen == 0:
                messagebox.showerror(
                    "Invalid Honeypot IP",
                    "Cannot use entire internet (0.0.0.0/0)."
                )
                return

    # ============================================================
    # WHITELIST / BLACKLIST CONFLICT DETECTION
    # ============================================================
    cursor.execute("SELECT whitelisted_ips, blacklisted_ips FROM settings LIMIT 1")
    row = cursor.fetchone()

    existing_whitelist = []
    existing_blacklist = []

    if row:
        if row[0]:
            existing_whitelist = [ip.strip() for ip in row[0].split(",") if ip.strip()]
        if row[1]:
            existing_blacklist = [ip.strip() for ip in row[1].split(",") if ip.strip()]

    if field == "whitelisted_ips":
        conflict = set(new_entries) & set(existing_blacklist)
    elif field == "blacklisted_ips":
        conflict = set(new_entries) & set(existing_whitelist)
    else:
        conflict = set()

    if conflict:
        messagebox.showerror(
            "Configuration Conflict",
            "These IPs already exist in opposite list:\n\n" +
            "\n".join(conflict)
        )
        return

    # ============================================================
    # PREVENT SELF LOCKOUT
    # ============================================================
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        if field == "blacklisted_ips":
            if local_ip in new_entries:
                messagebox.showerror(
                    "Critical Error",
                    "You are attempting to blacklist your own machine."
                )
                return
    except:
        pass

    # ============================================================
    # SAVE TO DATABASE
    # ============================================================
    cursor.execute(f"SELECT {field} FROM settings LIMIT 1")
    row = cursor.fetchone()

    existing_entries = []
    if row and row[0]:
        existing_entries = [ip.strip() for ip in row[0].split(",") if ip.strip()]

    added = [ip for ip in new_entries if ip not in existing_entries]
    removed = [ip for ip in existing_entries if ip not in new_entries]

    final_value = ",".join(new_entries)

    cursor.execute(
        f"UPDATE settings SET {field} = %s",
        (final_value,)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # ============================================================
    # USER FEEDBACK
    # ============================================================
    msg = "Settings updated successfully.\n"

    if added:
        msg += "\nAdded:\n" + "\n".join(added)

    if removed:
        msg += "\n\nRemoved:\n" + "\n".join(removed)

    if not added and not removed:
        msg += "\n\n(No changes detected)"

    messagebox.showinfo("Success", msg)
def reload_settings_ui():
    try:
        data = fetch_settings_data()
        if not data:
            return

        (
            email_val,
            email_token_val,
            suspicious_email_val,
            email_alerts_enabled,
            max_requests_json,
            honeypot_ips_val,
            sensitive_folders_val,
            remote_upload_val,
            whitelist_val,
            blacklist_val
        ) = data

        # ✅ SAFE CHECKS USING globals()

        if "new_email" in globals() and new_email:
            new_email.delete(0, "end")
            new_email.insert(0, email_val or "")

        if "email_api_token" in globals() and email_api_token:
            email_api_token.delete(0, "end")
            email_api_token.insert(0, email_token_val or "")

        if "suspicious_activity_alert_mail" in globals() and suspicious_activity_alert_mail:
            suspicious_activity_alert_mail.delete(0, "end")
            suspicious_activity_alert_mail.insert(0, suspicious_email_val or "")

        if "honeypot_ips" in globals() and honeypot_ips:
            honeypot_ips.delete(0, "end")
            honeypot_ips.insert(0, honeypot_ips_val or "")

        if "folder_path" in globals() and folder_path:
            folder_path.delete(0, "end")
            folder_path.insert(0, sensitive_folders_val or "")

        if "remote_upload_path" in globals() and remote_upload_path:
            remote_upload_path.delete(0, "end")
            remote_upload_path.insert(0, remote_upload_val or "")

        if "whitelist" in globals() and whitelist:
            whitelist.delete(0, "end")
            whitelist.insert(0, whitelist_val or "")

        if "blacklist" in globals() and blacklist:
            blacklist.delete(0, "end")
            blacklist.insert(0, blacklist_val or "")

        if "email_notify_var" in globals() and email_notify_var is not None:
            try:
                email_notify_var.set(bool(int(email_alerts_enabled)))
            except:
                email_notify_var.set(False)

    except Exception as e:
        print("Settings reload error:", e)
    except Exception as e:
        print("Settings reload error:", e)



def settingshow(setnum):
    global admin_user, email, admin_pass, max_requests_per_minute, time_limit, honeypot_ips
    global sensative_folder, folder_path, allowed_ports, port_services, form_container
    global image_container, new_email, whitelist, blacklist, interval_var, request_limit_var 
    global port, service, email_notify_var,remote_upload_path,email_api_token, suspicious_activity_alert_mail


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
        sidebar.grid_remove()
        sidebar.grid_propagate(False)

        sidebar.configure(width=180)
        sidebar.lift()

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

            # ================== ROW BUILDER ==================
            def add_setting_row(parent, row, label_text, widget_type="entry", cmd=None, var=None):
                row_frame = tk.Frame(parent, bg=CARD_BG,
                                    highlightbackground=BORDER_LIGHT,
                                    highlightthickness=1)
                row_frame.grid(row=row, column=0, sticky="ew", pady=6)
                row_frame.columnconfigure(1, weight=1)

                label_container = tk.Frame(row_frame, bg=CARD_BG)
                label_container.grid(row=0, column=0, padx=(22, 10), pady=18, sticky="w")

                tk.Label(
                    label_container,
                    text=label_text,
                    font=("Segoe UI Semibold", 10),
                    bg=CARD_BG,
                    fg=TEXT_SUB
                ).pack(side="left")

                if widget_type == "entry":
                    ent = ttk.Entry(row_frame)
                    ent.grid(row=0, column=1, sticky="ew", padx=10)

                    if cmd:
                        tk.Button(
                            row_frame, text="UPDATE", command=cmd,
                            bg=CARD_BG, fg=ACCENT_BLUE, relief="flat",
                            font=("Segoe UI", 9, "bold"), padx=16, pady=4,
                            cursor="hand2", activebackground=HOVER_GRAY
                        ).grid(row=0, column=2, padx=(10, 22))
                    ent._row_frame = row_frame
                    return ent

                elif widget_type == "check":
                    cb = ttk.Checkbutton(row_frame, variable=var)
                    cb.grid(row=0, column=1, sticky="w", padx=10)
                    
                    # Checkboxes in this UI also use an update button to trigger the DB call
                    tk.Button(
                        row_frame, text="UPDATE", command=cmd,
                        bg=CARD_BG, fg=ACCENT_BLUE, relief="flat",
                        font=("Segoe UI", 9, "bold"), padx=16, pady=4,
                        cursor="hand2", activebackground=HOVER_GRAY
                    ).grid(row=0, column=2, padx=(10, 22))
                    return cb

            # ================== MAIN VIEW & SCROLLBAR ==================
            main_view = tk.Frame(content_frame, bg=BG_COLOR)
            main_view.pack(fill="both", expand=True)

            header = tk.Frame(main_view, bg=BG_COLOR)
            header.pack(fill="x", padx=80, pady=(30, 15))

            tk.Label(header, text="System Configuration", font=("Segoe UI Variable Display", 26, "bold"),
                    bg=BG_COLOR, fg=TEXT_MAIN).pack(anchor="w")

            canvas_container = tk.Frame(main_view, bg=BG_COLOR)
            canvas_container.pack(fill="both", expand=True, padx=40, pady=10)

            canvas = tk.Canvas(canvas_container, bg=BG_COLOR, highlightthickness=0)
            canvas.pack(side="left", fill="both", expand=True)

            scrollbar = ttk.Scrollbar(canvas_container, orient="vertical", command=canvas.yview)
            scrollbar.pack(side="right", fill="y")
            canvas.configure(yscrollcommand=scrollbar.set)

            settings_container = tk.Frame(canvas, bg=BG_COLOR)
            window_id = canvas.create_window((0, 0), window=settings_container, anchor="nw")
            canvas.bind("<Configure>", lambda e: canvas.itemconfig(window_id, width=e.width))
            settings_container.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

            # ================== GENERAL SETTINGS ==================
            general_card = ttk.LabelFrame(settings_container, text=" General Settings ")
            general_card.pack(fill="x", pady=18)

            # ---------- Alert Email ----------
            new_email = add_setting_row(
                general_card,
                0,
                "System Alert Email",
                cmd=lambda: update_setting("new email")
            )

             # ---------- Email API Token ----------
            email_api_token = add_setting_row(
            general_card,
            1,
            "Email API Token (Resend)",
            cmd=lambda: update_setting("email_api_token")
        )

            email_token_row = email_api_token._row_frame


            # ---------- TEST EMAIL BUTTON ----------
            tk.Button(
                email_token_row,
                text="TEST EMAIL",
                bg="#10b981",          # green
                fg="white",
                relief="flat",
                font=("Segoe UI", 9, "bold"),
                padx=12,
                pady=4,
                cursor="hand2",
                activebackground="#059669",
                command=lambda: update_setting("test_email_token")
            ).grid(row=0, column=3, padx=(6, 18))

            # ---------- Enable / Disable All Email Notifications ----------
            if 'email_notify_var' not in globals():
                email_notify_var = tk.BooleanVar()

            enable_email_cb = add_setting_row(
                general_card,
                2,
                "Enable Email Notifications",
                widget_type="check",
                var=email_notify_var,
                cmd=lambda: update_setting("email_notifications")
            )

            # ---------- Suspicious Activity Alert Email (TEXTBOX) ----------
            suspicious_activity_alert_mail = add_setting_row(
                general_card,
                3,
                "Suspicious Activity Alert Email",
                cmd=lambda: update_setting("suspicious_activity_alert_mail")
            )

            # ================== TRAFFIC CONTROLS ==================
            limit_card = ttk.LabelFrame(settings_container, text=" Traffic Controls ")
            limit_card.pack(fill="x", pady=18)

            # Rule Engine (Interval & Request limit)
            rule_row = tk.Frame(
                limit_card,
                bg=CARD_BG,
                highlightbackground=BORDER_LIGHT,
                highlightthickness=1
            )
            rule_row.grid(row=0, column=0, sticky="ew", pady=6)
            rule_row.columnconfigure(1, weight=1)

            tk.Label(
                rule_row,
                text="Traffic Rule (Interval(time) → Requests(request time))",
                font=("Segoe UI Semibold", 10),
                bg=CARD_BG,
                fg=TEXT_SUB,
                width=34,
                anchor="w"
            ).grid(row=0, column=0, padx=(22, 10), pady=18)

            ctrl = tk.Frame(rule_row, bg=CARD_BG)
            ctrl.grid(row=0, column=1, sticky="w")

            # Shared variables
            interval_var = tk.StringVar(value="1")
            request_limit_var = tk.StringVar(value="100")

            ttk.Combobox(
                ctrl,
                textvariable=interval_var,
                values=[1, 2, 5, 10, 20, 30],
                width=6,
                state="normal"
            ).pack(side="left", padx=(0, 10))

            ttk.Combobox(
                ctrl,
                textvariable=request_limit_var,
                values=[50, 100, 200, 500, 1000, 5000],
                width=8,
                state="normal"
            ).pack(side="left")

            tk.Button(
                rule_row,
                text="APPLY POLICY",
                bg=ACCENT_BLUE,
                fg="white",
                relief="flat",
                font=("Segoe UI", 9, "bold"),
                padx=18,
                pady=6,
                cursor="hand2",
                command=lambda: update_setting("max_requests_per_minute")
            ).grid(row=0, column=2, padx=(10, 22))

            # ================== EXISTING TRAFFIC RULES ==================
            rules_container = tk.Frame(limit_card, bg=CARD_BG)
            rules_container.grid(row=1, column=0, sticky="ew", padx=22, pady=(8, 14))

            tk.Label(
            rules_container,
            text="Existing Traffic Rules",
            font=("Segoe UI Semibold", 10),
            bg=CARD_BG,
            fg=TEXT_SUB,
            anchor="w"
        ).pack(anchor="w", pady=(0, 6))

            rules_listbox = tk.Listbox(
            rules_container,
           
            font=("Segoe UI", 9),
            selectmode="single",
            activestyle="none"
        )
            rules_listbox.pack(fill="x", pady=(0, 10))

            tk.Button(
            rules_container,
            text="DELETE SELECTED RULE",
            bg="#C0392B",
            fg="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=14,
            pady=6,
            cursor="hand2",
            command=lambda: manage_traffic_rules("delete", rules_listbox)
            ).pack(anchor="e")
            manage_traffic_rules("load", rules_listbox)

            # ================== NETWORK INTELLIGENCE ==================
            security_card = ttk.LabelFrame(settings_container, text=" Network Intelligence ")
            security_card.pack(fill="x", pady=18)

            honeypot_ips = add_setting_row(
                security_card,
                0,
                "Honeypot IP",
                cmd=lambda: update_setting("honeypot_ips")
            )

            folder_path = add_setting_row(
                security_card,
                1,
                "Protected Directory",
                cmd=lambda: update_setting("sensitive folder")
            )

            # ---------- Remote Upload Directory (DESTINATION) ----------
            remote_upload_path = add_setting_row(
                security_card,
                2,
                "Remote Upload Directory (On Attack)",
                cmd=lambda: update_setting("remote_upload_directory")
            )
                        # ---------- DECRYPT SENSITIVE FILE BUTTON ----------
            tk.Button(
                security_card,
                text="🔓 Decrypt Protected File",
                bg="#8e44ad",
                fg="white",
                font=("Segoe UI", 9, "bold"),
                relief="flat",
                cursor="hand2",
                padx=14,
                pady=6,
                activebackground="#732d91",
                command=lambda: update_setting("decrypt_file")
            ).grid(row=3, column=0, columnspan=3, sticky="w", padx=22, pady=(6, 10))
            whitelist = add_setting_row(
                security_card,
                4,
                "Permitted IP List",
                cmd=lambda: handle_network_setting("update", "whitelisted_ips", whitelist)
            )

            blacklist = add_setting_row(
                security_card,
                5,
                "Restricted IP List",
                cmd=lambda: handle_network_setting("update", "blacklisted_ips", blacklist)
            )
            

            # ================== LOAD & VERIFY DATA ==================

            reload_settings_ui()



            data = fetch_settings_data()
            if data:
                # 1. Clear existing data and verify/insert fresh data from DB
                # Assumption: data tuple indexes match your fetch_settings_data() query
                # Order: phone[0], email[1], interval[2], limit[3], honey[4], folder[6], white[7], black[8], alerts[9]
                
                mapping = [
                    (new_email, data[0])
                    
                ]

                for widget, db_value in mapping:
                    if widget and db_value is not None:
                        widget.delete(0, 'end')  # Verification: Clear before insert
                        widget.insert(0, str(db_value))

                # 2. Update Traffic Rule Vars
                #if data[2]: interval_var.set(str(data[2]))
                #if data[3]: request_limit_var.set(str(data[3]))

                
# ================= LOGIN FIELD HELPER =================
OTP_DATA = {"otp": None}

import random
import bcrypt
import sys
from tkinter import messagebox
from securegate_new import EMERGENCY_ALERT
import resend


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
    #entry.pack(fill="x", pady=8)

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

        # ================= STEP 1: SEND OTP =================
        if step["value"] == 1:
            cursor.execute("SELECT email FROM settings WHERE id = 1")
            row = cursor.fetchone()

            if not row or not row[0]:
                messagebox.showerror(
                    "Error",
                    "Registered admin email not found."
                )
                return

            otp = str(random.randint(100000, 999999))
            OTP_DATA["otp"] = otp

          
            try:
                # -------- FETCH EMAIL + API TOKEN FROM DB --------
                conn, cursor = db()

                cursor.execute("""
                    SELECT email_token, email
                    FROM settings
                    WHERE id = 1
                    LIMIT 1
                """)
                row = cursor.fetchone()

                if not row:
                    messagebox.showerror("Email Error", "Email settings not found.")
                    return

                api_token, sender_email = row
                receiver_email = sender_email  # OTP goes to admin email

                if not api_token:
                    messagebox.showerror("Email Error", "Resend API token missing.")
                    return

                cursor.close()
                conn.close()

                # -------- SET RESEND API KEY --------
                resend.api_key = api_token

                # -------- SEND OTP EMAIL --------
                resend.Emails.send({
                    "from": "onboarding@resend.dev",
                    "to": receiver_email,
                    "subject": "SecureGate Password Reset OTP",
                    "html": f"""
                    <h3>SecureGate Password Reset OTP</h3>
                    <p>Your OTP is:</p>
                    <h2 style="letter-spacing:2px">{otp}</h2>
                    <p><b>Do not share this OTP with anyone.</b></p>
                    <p>If you did not request a password reset, contact admin immediately.</p>
                    """
                })
                info_lbl.config(
            text="OTP has been sent to your email.\nEnter OTP to continue."
        )
            except Exception as e:
                messagebox.showerror(
                    "Email Error",
                    f"Failed to send OTP.\n\n{e}"
                )

                return

            

            entry.delete(0, "end")
            entry.pack(fill="x", pady=8)   # 👈 SHOW INPUT NOW

            action_btn.config(text="VERIFY OTP")
            step["value"] = 2

        # ================= STEP 2: VERIFY OTP =================
        elif step["value"] == 2:
            user_otp = entry.get().strip()

            if not OTP_DATA["otp"]:
                messagebox.showerror("Error", "OTP session expired.")
                win.destroy()
                return

            if user_otp != OTP_DATA["otp"]:
                messagebox.showerror("Invalid OTP", "Incorrect OTP entered.")
                exit()
                return

            # OTP VERIFIED → invalidate immediately
            OTP_DATA["otp"] = None

            info_lbl.config(text="Set new password")
            entry.destroy()

            pwd1 = ttk.Entry(frame, show="*")
            pwd1.pack(fill="x", pady=6)

            pwd2 = ttk.Entry(frame, show="*")
            pwd2.pack(fill="x", pady=6)

            step["pwd1"] = pwd1
            step["pwd2"] = pwd2

            action_btn.config(text="RESET PASSWORD")
            step["value"] = 3

        # ================= STEP 3: RESET PASSWORD =================
        elif step["value"] == 3:
            pwd1 = step["pwd1"].get()
            pwd2 = step["pwd2"].get()

            if pwd1 != pwd2:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            if len(pwd1) < 8:
                messagebox.showerror(
                    "Weak Password",
                    "Password must be at least 8 characters long."
                )
                return

            hashed = bcrypt.hashpw(
                pwd1.encode(),
                bcrypt.gensalt()
            ).decode()

            cursor.execute(
                "UPDATE settings SET password_hash=%s WHERE id=1",
                (hashed,)
            )
            conn.commit()

            messagebox.showinfo(
                "Success",
                "Password reset successful.\nPlease login again."
            )

            win.destroy()

        cursor.close()
        conn.close()

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
    global admin_user, email, form_container, admin_pass, time_limit
    global honeypot_ips, folder_path, allowed_ports, port_services
    global whitelist, blacklist, interval_var, request_limit_var
    global port, service, email_notify_var, new_email, max_requests_per_minute
    global email_api_token, suspicious_activity_alert_mail,remote_upload_path


    # ---------- REGEX PATTERNS ----------
    USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")
    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$")
    PORTS_REGEX = re.compile(r"^(\d{1,5})(,\d{1,5})*$")
    PATH_REGEX = re.compile(r"^[a-zA-Z0-9_\/\\\:\.-]+$")
    
    dt = db()
    connection = dt[0]
    cursor = dt[1]

    # Helper function to get current value for duplicate checking
    def get_current_setting(column):
        cursor.execute(f"SELECT {column} FROM settings LIMIT 1")
        res = cursor.fetchone()
        return str(res[0]) if res else None

    
    # ================= EMAIL =================
        # ================= ADMIN SIGN-IN / ACCOUNT CREATION =================
    if val == "sign in":
        username = admin_user.get().strip()
        email_val = email.get().strip()
        password = admin_pass.get().strip()

        # ---------- VALIDATION ----------
        if not USERNAME_REGEX.match(username):
            messagebox.showerror(
                "Invalid Username",
                "Username must be 3–30 characters.\nAllowed: letters, numbers, . _ -"
            )
            return

        if not EMAIL_REGEX.match(email_val):
            messagebox.showerror("Invalid Email", "Enter a valid email address.")
            return

        if not PASSWORD_REGEX.match(password):
            messagebox.showerror(
                "Weak Password",
                "Password must contain:\n"
                "• At least 8 characters\n"
                "• One uppercase letter\n"
                "• One lowercase letter\n"
                "• One number\n"
                "• One special character"
            )
            return

        # ---------- CHECK IF ADMIN ALREADY EXISTS ----------
        cursor.execute("SELECT admin_name FROM settings LIMIT 1")
        if cursor.fetchone():
            messagebox.showwarning(
                "Admin Exists",
                "An admin account already exists.\nPlease log in instead."
            )
            return

        # ---------- HASH PASSWORD (bcrypt) ----------
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # ---------- INSERT INTO DATABASE ----------
        cursor.execute("""
            INSERT INTO settings (admin_name, email, password_hash)
            VALUES (%s, %s, %s)
        """, (username, email_val, hashed_password))

        connection.commit()

        messagebox.showinfo(
            "Success",
            "Admin account created successfully.\nPlease log in."
        )

        # Redirect to login screen
        settingshow(2)
        reload_settings_ui()


    elif val == "new email":
        new_val = new_email.get().strip()
        if not EMAIL_REGEX.match(new_val):
            messagebox.showerror("Invalid Email", "Enter a valid email address.")
            return

        if new_val == get_current_setting("email"):
            messagebox.showinfo("No Change", "This email is already registered.")
            return

        cursor.execute("UPDATE settings SET email = %s", (new_val,))
        connection.commit()
        messagebox.showinfo("Success", "Alert email updated.")
    

    elif val == "email_api_token":
        token = email_api_token.get().strip()

        if not token:
            messagebox.showerror("Invalid Token", "API token cannot be empty.")
            return

        if token == get_current_setting("email_token"):
            messagebox.showinfo("No Change", "This API token is already saved.")
            return

        cursor.execute(
            "UPDATE settings SET email_token = %s",
            (token,)
        )
        connection.commit()
        reload_settings_ui()
        messagebox.showinfo("Success", "Email API token updated.")


    # ================= RATE LIMIT =================
    elif val == "max_requests_per_minute":
        interval = interval_var.get()
        limit = request_limit_var.get()

        if not interval.isdigit() or not limit.isdigit():
            messagebox.showerror("Invalid Input", "Interval and limit must be numbers.")
            return

        # Assuming jsonins handles its own internal duplicate check/logic
        jsonins("rqpt", interval, limit)
        messagebox.showinfo("Success", f"Traffic policy updated: {limit} reqs / {interval} min.")



    elif val == "suspicious_activity_alert_mail":
        email_value = suspicious_activity_alert_mail.get().strip()

        # Empty = disable suspicious alerts
        if email_value == "":
            cursor.execute(

                "UPDATE settings SET suspicious_activity_alert_mail = NULL"
            )
            connection.commit()
            reload_settings_ui()
            messagebox.showinfo(
                "Updated",
                "Suspicious activity email alerts disabled."
            )
            return

        # Validate email format
        if not EMAIL_REGEX.match(email_value):
            messagebox.showerror(
                "Invalid Email",
                "Enter a valid email address for suspicious activity alerts."
            )
            return

        if email_value == get_current_setting("suspicious_activity_alert_mail"):
            messagebox.showinfo("No Change", "This email is already set.")
            return

        cursor.execute(
            "UPDATE settings SET suspicious_activity_alert_mail = %s",
            (email_value,)
        )
        connection.commit()
        reload_settings_ui()
        messagebox.showinfo(
            "Success",
            "Suspicious activity alert email updated."
        )

    
    elif val == "remote_upload_directory":
            upload_path = remote_upload_path.get().strip()

            if not PATH_REGEX.match(upload_path):
                messagebox.showerror(
                    "Invalid Path",
                    "Invalid remote upload directory format."
                )
                return

            if upload_path == get_current_setting("remote_upload_directory"):
                messagebox.showinfo(
                    "No Change",
                    "This remote upload directory is already set."
                )
                return

            cursor.execute(
                "UPDATE settings SET remote_upload_directory = %s",
                (upload_path,)
            )
            connection.commit()
            reload_settings_ui()
            messagebox.showinfo(
                "Success",
                "Remote upload directory updated successfully."
            )


    elif val == "test_email_token":
        try:
            # ---------- FETCH EMAIL SETTINGS FROM DB ----------
            conn, cursor = db()

            cursor.execute("""
                SELECT email_token, suspicious_activity_alert_mail
                FROM settings
                LIMIT 1
            """)
            row = cursor.fetchone()

            cursor.close()
            conn.close()

            if not row:
                raise Exception("Email configuration not found in database.")

            api_token, receiver_email = row

            if not api_token:
                raise Exception("Resend API token is not configured.")

            if not receiver_email:
                raise Exception("Recipient email address is missing.")

            # ---------- CONFIGURE RESEND ----------
            resend.api_key = api_token

            # ---------- BUILD TEST EMAIL ----------
            subject = "🚨 SecureGate Test Alert – Email System Verification"

            html_message = f"""
            <div style="font-family:Segoe UI,Arial,sans-serif">
                <h2 style="color:#dc2626">SecureGate – Test Security Alert</h2>
                <p>This is a <b>test email</b> to verify your email alert configuration.</p>

                <table cellpadding="6" cellspacing="0" border="0">
                    <tr><td><b>Alert Type:</b></td><td>Intrusion (TEST)</td></tr>
                    <tr><td><b>Source IP:</b></td><td>127.0.0.1</td></tr>
                    <tr><td><b>Protocol:</b></td><td>TEST_EMAIL</td></tr>
                    <tr><td><b>Timestamp:</b></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                </table>

                <p style="margin-top:12px;color:#555">
                    If you received this email, your SecureGate email system is working correctly.
                </p>
            </div>
            """

            # ---------- SEND EMAIL ----------
            resend.Emails.send({
                "from": "SecureGate <onboarding@resend.dev>",
                "to": receiver_email,
                "subject": subject,
                "html": html_message
            })

            messagebox.showinfo(
                "Test Email Sent",
                "Test email sent successfully.\nPlease check your inbox."
            )

        except Exception as e:
            messagebox.showerror(
                "Test Email Failed",
                f"Unable to send test email.\n\n{e}"
            )


    # ================= HONEYPOT =================
    elif val == "honeypot_ips":
        ip_val = honeypot_ips.get().strip()
        if not (IPV4_REGEX.match(ip_val) or IPV6_REGEX.match(ip_val)):
            messagebox.showerror("Invalid IP", "Enter a valid IPv4 or IPv6 address.")
            return

        # Check existing via your specialized function
        ins_honey(ip_val) 
        # (Note: Ensure ins_honey provides its own success messagebox)

    # ================= SENSITIVE FOLDER =================
    elif val == "sensitive folder":
        path = folder_path.get().strip()

        if path == "":
            cursor.execute("UPDATE settings SET sensitive_folders = NULL")
            connection.commit()
            messagebox.showinfo("Feature Disabled", "Protected path cleared.")
            return

        if not os.path.exists(path):
            messagebox.showerror(
                "Invalid Path",
                "The specified file or directory does not exist."
            )
            return

        if not os.access(path, os.R_OK):
            messagebox.showerror(
                "Permission Error",
                "Application does not have permission to access this path."
            )
            return

        cursor.execute("UPDATE settings SET sensitive_folders = %s", (path,))
        connection.commit()
        messagebox.showinfo("Success", "Protected path updated.")
    # ================= EMAIL NOTIFICATION (Toggle) =================
    elif val == "email_notifications":
        new_state = 1 if email_notify_var.get() else 0
        current_state = get_current_setting("email_alerts_enabled")
        
        if str(new_state) == str(current_state):
            messagebox.showinfo("No Change", "Notification setting is already at this state.")
            return

        cursor.execute("UPDATE settings SET email_alerts_enabled = %s", (new_state,))
        connection.commit()
        status = "enabled" if new_state else "disabled"
        messagebox.showinfo("Success", f"Real-time notifications {status}.")

    elif val == "decrypt_file":
        success = decrypt_sensitive_file()

        if success:
            messagebox.showinfo(
                "Decryption Successful",
                "Encrypted file has been successfully decrypted."
            )
        else:
            messagebox.showwarning(
                "Decryption Failed",
                "No encrypted file found or file already decrypted."
            )
        

def toggle_network_monitor():
    global SECUREGATE_NETWORK_MONITOR, network_monitor_btn

    load_dotenv(ENV_FILE, override=True)

    current_value = os.getenv("SECUREGATE_NETWORK_MONITOR", "False").lower()
    new_value = "True" if current_value == "false" else "False"

    # If turning ON → perform validation first
    if new_value == "True":

        conn, cursor = db()
        if not conn:
            messagebox.showerror("Database Error", "Unable to verify configuration.")
            return

        cursor.execute("""
            SELECT honeypot_ips,
                whitelisted_ips,
                blacklisted_ips,
                sensitive_folders
            FROM settings
            LIMIT 1
        """)

        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row:
            messagebox.showerror("Configuration Error", "System settings not found.")
            return

        honeypot, whitelist, blacklist, folder = row

        warnings = []
        critical = []

        # -------- BASIC CHECKS --------
        if not honeypot:
            warnings.append("• Honeypot IP is not configured.")

        if not whitelist:
            warnings.append("• Whitelist IP list is empty.")

        if not blacklist:
            warnings.append("• Blacklist IP list is empty.")

        if not folder:
            warnings.append("• Protected directory is not set.")

        # -------- ADVANCED NETWORK SAFETY CHECKS --------
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8")
        ]

        # Check if blacklist blocks internal ranges
        if blacklist:
            for ip in blacklist.split(","):
                ip = ip.strip()
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    for net in private_ranges:
                        if ip_obj in net:
                            critical.append(
                                f"• Internal IP {ip} is blacklisted.\n  This may block internal network communication."
                            )
                except:
                    pass

        # Check if honeypot equals localhost
        if honeypot and honeypot.strip() == "127.0.0.1":
            critical.append(
                "• Honeypot IP is set to localhost (127.0.0.1).\n  This may create redirection loops."
            )

        # -------- BUILD MESSAGE --------
        if warnings or critical:

            message = "⚠ SecureGate Pre-Launch Risk Assessment\n\n"

            if critical:
                message += "🚨 CRITICAL RISKS DETECTED:\n\n"
                message += "\n\n".join(critical)
                message += "\n\n"

            if warnings:
                message += "⚠ Configuration Warnings:\n\n"
                message += "\n".join(warnings)
                message += "\n\n"

            message += (
                "Starting monitoring with these issues may:\n"
                "• Block internal network topology\n"
                "• Lock you out of your own system\n"
                "• Cause routing failures\n"
                "• Disrupt normal traffic flow\n\n"
                "Are you sure you want to continue?"
            )

            confirm = messagebox.askyesno(
                "SecureGate Risk Warning",
                message
            )

            if not confirm:
                return
    # ---- UPDATE ENV FILE ----
    lines = []
    found = False

    with open(ENV_FILE, "r") as f:
        for line in f:
            if line.startswith("SECUREGATE_NETWORK_MONITOR"):
                lines.append(f"SECUREGATE_NETWORK_MONITOR={new_value}\n")
                found = True
            else:
                lines.append(line)

    if not found:
        lines.append(f"\nSECUREGATE_NETWORK_MONITOR={new_value}\n")

    with open(ENV_FILE, "w") as f:
        f.writelines(lines)

    os.environ["SECUREGATE_NETWORK_MONITOR"] = new_value
    SECUREGATE_NETWORK_MONITOR = new_value.lower() == "true"

    # ---- Update Button UI Only ----
    if SECUREGATE_NETWORK_MONITOR:
        network_monitor_btn.config(
            text="🟢 Network Monitor: ON",
            bg="#2ecc71",
            activebackground="#27ae60"
        )
    else:
        network_monitor_btn.config(
            text="🔴 Network Monitor: OFF",
            bg="#e74c3c",
            activebackground="#c0392b"
        )

def dashboardshow():
    global APP_STATE, network_monitor_btn, refresh_jobs

    # 🔴 Reset state and clear background jobs
    clear_all_jobs()

    APP_STATE["current_view"] = "dashboard"
    APP_STATE["current_page"] = 0
    APP_STATE["last_page_name"] = None
    sidebar.grid(row=0, column=0, sticky="ns")

    # Clear everything from the main content area
    for widget in content_frame.winfo_children():
        widget.destroy()

    # --- THEME COLORS ---
    BG_MAIN = "#f4f7f6"
    CARD_BG = "#ffffff"
    ALERT_RED = "#e74c3c"
    ACCENT_COLOR = "#2c3e50"

    # =================================================================
    # 1. FIXED SCROLLBAR ARCHITECTURE
    # =================================================================
    
    # Outer container to hold canvas + scrollbar
    container = tk.Frame(content_frame, bg=BG_MAIN)
    container.pack(fill="both", expand=True)

    canvas = tk.Canvas(container, bg=BG_MAIN, highlightthickness=0)
    scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    
    # This is the "inner" frame that will expand to full width
    scrollable_dashboard = tk.Frame(canvas, bg=BG_MAIN)

    # Update scroll region whenever widgets are added
    scrollable_dashboard.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    # Place frame inside canvas
    window_id = canvas.create_window((0, 0), window=scrollable_dashboard, anchor="nw")

    # 🔥 CRITICAL FIX: This forces the dashboard to stay full-width
    def on_canvas_configure(event):
        canvas.itemconfig(window_id, width=event.width)

    canvas.bind("<Configure>", on_canvas_configure)
    canvas.configure(yscrollcommand=scrollbar.set)

    # Pack scrollbar and canvas correctly
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    # =================================================================
    # 2. DASHBOARD CONTENT (Using 'scrollable_dashboard' as parent)
    # =================================================================

    # ---------------- HEADER ----------------
    header_frame = tk.Frame(scrollable_dashboard, bg=BG_MAIN)
    header_frame.pack(fill="x", padx=30, pady=(20, 10))

    btn_text = "🟢 Network Monitor: ON" if SECUREGATE_NETWORK_MONITOR else "🔴 Network Monitor: OFF"
    btn_color = "#2ecc71" if SECUREGATE_NETWORK_MONITOR else "#e74c3c"
    active_color = "#27ae60" if SECUREGATE_NETWORK_MONITOR else "#c0392b"

    network_monitor_btn = tk.Button(
        header_frame, text=btn_text, font=("Segoe UI", 10, "bold"),
        fg="white", bg=btn_color, activebackground=active_color,
        relief="flat", cursor="hand2", padx=15, pady=6,
        command=toggle_network_monitor
    )
    network_monitor_btn.pack(side="right", padx=10)

    # ---------------- ALERTS SECTION ----------------
    alerts_container = tk.LabelFrame(
        scrollable_dashboard, text=" 🚨 ACTIVE SECURITY THREATS ",
        font=("Segoe UI", 11, "bold"), fg=ALERT_RED, bg=CARD_BG,
        padx=15, pady=15, relief="flat", highlightbackground="#dcdde1", highlightthickness=1
    )
    alerts_container.pack(fill="x", padx=30, pady=10)

    # Alert Treeview Logic (Standardized for Scrollable Frame)
    table_frame = tk.Frame(alerts_container, bg=CARD_BG)
    table_frame.pack(fill="x", expand=True)

    columns_alert = ("attack_type", "src_ip", "first_detected", "last_detected", "hit_count", "severity")
    
    alert_tree = ttk.Treeview(table_frame, columns=columns_alert, show="headings", height=5, style="Alert.Treeview")
    alert_tree.pack(fill="x", expand=True, side="left")

    for col in columns_alert:
        alert_tree.heading(col, text=col.replace("_", " ").title())
        alert_tree.column(col, anchor="center", width=100)

    # Fetch and Insert Rows
    try:
        conn, cur = db()
        cur.execute("SELECT attack_type, src_ip, first_detected, last_detected, hit_count, severity FROM attack_state WHERE is_active = 1")
        rows = cur.fetchall()
        if not rows:
            alert_tree.destroy()
            tk.Label(table_frame, text="🛡 No Active Security Threats Detected", font=("Segoe UI", 11, "bold"), bg=CARD_BG, fg="#2ecc71", pady=15).pack()
        else:
            for r in rows:
                alert_tree.insert("", "end", values=r)
        cur.close()
        conn.close()
    except:
        pass

    # ---------------- CHARTS SECTION ----------------
    tk.Label(scrollable_dashboard, text="Geographic Traffic Analysis", 
             font=("Segoe UI", 14, "bold"), fg=ACCENT_COLOR, bg=BG_MAIN).pack(anchor="w", padx=30, pady=(20, 5))

    # Pass the scrollable frame to ensure charts don't float outside
    show_country_heat_chart(scrollable_dashboard)
    show_bar_chart_by_country_integrated(scrollable_dashboard)

    # ---------------- REFRESH LOGIC ----------------
    thread = threading.Thread(target=update_null_countries)
    thread.daemon = True
    thread.start()

    job_id = root.after(SECUREGATE_GUI_REFRESH_INTERVAL * 1000, dashboardshow)
    refresh_jobs.append(job_id)

def show_bar_chart_by_country_integrated(parent):
    # 1. Fetch data from database
    blocked = fetch_ips("blocked") or []
    unblocked = fetch_ips("unblocked") or []

    # 2. Process data into counts
    blocked_counts = collections.defaultdict(int)
    for ip, country in blocked:
        name = str(country).strip() if country and str(country).strip() != "" else "Unknown"
        blocked_counts[name] += 1

    unblocked_counts = collections.defaultdict(int)
    for ip, country in unblocked:
        name = str(country).strip() if country and str(country).strip() != "" else "Unknown"
        unblocked_counts[name] += 1

    # 🔥 FIX: Define all_countries here so the loop below can find it
    all_countries = sorted(list(set(blocked_counts.keys()) | set(unblocked_counts.keys())))

    if not all_countries:
        tk.Label(parent, text="No Data Available", bg="#f4f7f6").pack(pady=20)
        return

    # --- CHART CARD ---
    chart_card = tk.Frame(parent, bg="white", highlightbackground="#dcdde1", highlightthickness=1)
    chart_card.pack(fill="x", padx=30, pady=10)

    fig, ax = plt.subplots(figsize=(10, 4), dpi=100)
    width = 0.35
    x = range(len(all_countries))

    ax.bar(x, [blocked_counts.get(c, 0) for c in all_countries], width, label='Blocked', color="#e74c3c")
    ax.bar([i + width for i in x], [unblocked_counts.get(c, 0) for c in all_countries], width, label='Unblocked', color="#2ecc71")
    
    ax.set_xticks([i + width / 2 for i in x])
    ax.set_xticklabels(all_countries, rotation=25, ha='right', fontsize=8)
    ax.legend()
    fig.tight_layout()

    canvas = FigureCanvasTkAgg(fig, master=chart_card)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

    # --- DATA TABLE CARD ---
    table_frame = tk.Frame(parent, bg="#f4f7f6")
    table_frame.pack(fill='both', expand=True, padx=30, pady=(10, 20))

    columns = ('country', 'blocked', 'unblocked')
    tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=10)

    for col in columns:
        tree.heading(col, text=col.upper())
        tree.column(col, anchor='center')

    # This loop now works because all_countries is defined above
    for i, country in enumerate(all_countries):
        tree.insert('', 'end', values=(country, blocked_counts.get(country, 0), unblocked_counts.get(country, 0)))

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
        "Protocol Monitor": "network_protocol",
        "blocked IP": "ip" # We filter this in the query usually
    }
    return mapping.get(page, page)

def blockdatashow():
    database = db()
    conn = database[0]
    cursor = database[1]

    cursor.execute("SELECT * FROM ip WHERE is_blocked = 1")

    all_rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    return all_rows, columns







import threading

def update_gui_with_data(fetched_rows, cols, page_name, reset_pagination=True):
    global all_rows, columns, APP_STATE, original_rows

    if fetched_rows == "dashboard":
        APP_STATE["current_view"] = "dashboard"
        dashboardshow()
        return

    elif fetched_rows == "settings":
        APP_STATE["current_view"] = "settings"
        settingshow(3)
        return

    # ---------------- FIRST: Assign Data ----------------
    all_rows = fetched_rows if fetched_rows else []
    columns = cols if cols else []
    original_rows = list(all_rows)

    # ---------------- THEN: Re-Apply Sorting ----------------
    if APP_STATE.get("sort_column") and APP_STATE["sort_column"] in columns:

        col_name = APP_STATE["sort_column"]
        col_index = columns.index(col_name)

        def sort_key(row):
            value = row[col_index]

            if value is None:
                return ""

            value_str = str(value).strip()

            # IP sort
            try:
                ip_obj = ipaddress.ip_address(value_str)
                return (ip_obj.version, int(ip_obj))
            except:
                pass

            # Number sort
            try:
                return float(value_str)
            except:
                pass

            # Datetime sort
            try:
                return datetime.strptime(value_str, "%Y-%m-%d %H:%M:%S")
            except:
                pass

            return value_str.lower()

        all_rows.sort(
            key=sort_key,
            reverse=APP_STATE.get("sort_reverse", False)
        )

    # ---------------- Pagination Control ----------------
    if reset_pagination:
        APP_STATE["current_page"] = 0

    APP_STATE["current_view"] = "data_logs"
    APP_STATE["last_page_name"] = page_name

    show_page_data()

    # ---------------- Auto Refresh ----------------
    if page_name != "Setting":
        clear_all_jobs()
        job_id = root.after(
            SECUREGATE_GUI_REFRESH_INTERVAL * 1000,
            lambda: data_to_show(page_name, False)
        )
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
            "Protocol Monitor": "network_protocol",
       }

        fetched_rows = None
        dynamic_cols = []

        if page_name == "Dashboard":
            fetched_rows = "dashboard"
        elif page_name == "Setting":
            fetched_rows = "settings"
        
        else:
            if page_name == "blocked IP":
                fetched_rows, cols = blockdatashow()

                dynamic_cols = [c.replace("_", " ").title() for c in cols]

                root.after(
                    0,
                    lambda: update_gui_with_data(
                        fetched_rows,
                        dynamic_cols,
                        page_name,
                        reset_pagination
                    )
                )
                return



            # Get the table name from our mapping
            db_table = table_mapping.get(page_name)
            
            if db_table:
                if db_table != "iprequest_junction":
 
                    # 2. Execute a dynamic query
                    cursor.execute(f"SELECT * FROM {db_table}  ORDER BY last_seen  DESC  limit {SECUREGATE_GUI_LOAD_RECORD} ")
                else:
                    cursor.execute(f"SELECT * FROM {db_table}  ORDER BY request_time  DESC  limit {SECUREGATE_GUI_LOAD_RECORD} ")
             

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










root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
sidebar = tk.Frame(root, width=180, bg="#2c3e50")
sidebar.grid(row=0, column=0, sticky="ns")

sidebar.grid_propagate(False)  # 🔒 lock sidebar width

content_frame = tk.Frame(root, bg="white")
content_frame.grid(row=0, column=1, sticky="nsew")


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


    global all_rows, columns, current_page, rows_per_page, original_rows

    # ---------------- UI COLORS ----------------
    BG_MAIN = "#f4f7f6"
    CARD_BG = "#ffffff"
    ACCENT_BLUE = "#3498db"
    TEXT_COLOR = "#2c3e50"


    # ---------------- SAFE FILTER APPLICATION ----------------
    filtered_rows = all_rows

    filter_column = APP_STATE.get("filter_column")
    filter_value = APP_STATE.get("filter_value")
    
        # ---------------- APPLY FILTER ----------------
    if filter_column and filter_value and filter_column in columns:

        col_index = columns.index(filter_column)

        pattern = filter_value.strip().lower()

        temp = []

        for row in all_rows:
            cell_value = str(row[col_index]).strip().lower()

            # Contains search if % used
            if "%" in pattern:
                search = pattern.replace("%", "")
                if search in cell_value:
                    temp.append(row)
            else:
                # Default = starts with
                if cell_value.startswith(pattern):
                    temp.append(row)

        filtered_rows = temp
    
    # ---------------- RESET FRAME FIRST ----------------
    for widget in content_frame.winfo_children():
        widget.destroy()

    content_frame.configure(bg=BG_MAIN)

    # ---------------- PRESERVE STATE ----------------
    if not preserve_state:
        current_page = 0

    total_rows = len(filtered_rows)
    max_pages = max(0, (total_rows - 1) // rows_per_page)

    if current_page > max_pages:
        current_page = max_pages

    # ---------------- FILTER SECTION ----------------
    filter_frame = tk.Frame(content_frame, bg=BG_MAIN)
    filter_frame.pack(fill="x", padx=30, pady=(20, 5))

    tk.Label(
        filter_frame,
        text="Filter:",
        font=("Segoe UI", 10, "bold"),
        bg=BG_MAIN
    ).pack(side="left", padx=(0, 10))
    filter_column_var = tk.StringVar(
        value=APP_STATE.get("filter_column") or ""
    )


    column_dropdown = ttk.Combobox(
        filter_frame,
        textvariable=filter_column_var,
        values=columns,
        state="readonly",
        width=20
    )
    column_dropdown.pack(side="left", padx=5)

    filter_value_var = tk.StringVar(
        value=APP_STATE.get("filter_value") or ""
    )
    filter_entry = ttk.Entry(filter_frame, textvariable=filter_value_var, width=25)
    filter_entry.pack(side="left", padx=5)

    # 🔥 LIVE FILTER BIND
    def apply_filter_live(*args):
        selected_col = filter_column_var.get().strip()
        search_val = filter_value_var.get().strip()

        # If nothing selected → do nothing
        if not selected_col:
            return

        # If search box empty → reset filter
        if search_val == "":
            APP_STATE["filter_column"] = None
            APP_STATE["filter_value"] = None
            APP_STATE["current_page"] = 0
            show_page_data(preserve_state=True)
            return

        APP_STATE["filter_column"] = selected_col
        APP_STATE["filter_value"] = search_val
        APP_STATE["current_page"] = 0

        show_page_data(preserve_state=True)


    filter_value_var.trace_add("write", apply_filter_live)

    # ---------------- FILTER LOGIC ----------------
    
    def clear_filter():
        global all_rows, current_page
        filter_value_var.set("")
        all_rows = list(original_rows)
        current_page = 0
        show_page_data(preserve_state=True)
        APP_STATE["filter_column"] = None
        APP_STATE["filter_value"] = None
        APP_STATE["current_page"] = 0

        show_page_data(preserve_state=True)
    

    tk.Button(
        filter_frame,
        text="Clear",
        bg="#e74c3c",
        fg="white",
        relief="flat",
        cursor="hand2",
        command=clear_filter
    ).pack(side="left", padx=5)

    

    total_rows = len(filtered_rows)
    start = current_page * rows_per_page
    end = start + rows_per_page
    rows = filtered_rows[start:end]
    # ---------------- HEADER ----------------
    header_frame = tk.Frame(content_frame, bg=BG_MAIN)
    header_frame.pack(fill="x", padx=30, pady=(5, 10))

    tk.Label(
        header_frame,
        text="Network Data Logs",
        font=("Segoe UI", 18, "bold"),
        fg=TEXT_COLOR,
        bg=BG_MAIN
    ).pack(side="left")

    # ---------------- TABLE CONTAINER ----------------
    table_container = tk.Frame(
        content_frame,
        bg=CARD_BG,
        highlightbackground="#dcdde1",
        highlightthickness=1
    )
    table_container.pack(fill="both", expand=True, padx=30, pady=10)

    style = ttk.Style()
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
    style.configure("Treeview", rowheight=32, font=("Segoe UI", 10))

    if not rows:
        no_data_frame = tk.Frame(table_container, bg=CARD_BG)
        no_data_frame.pack(expand=True)
        tk.Label(
            no_data_frame,
            text="No Data Available",
            font=("Segoe UI", 12),
            fg="gray",
            bg=CARD_BG
        ).pack()
    else:
        v_scroll = ttk.Scrollbar(table_container, orient="vertical")
        h_scroll = ttk.Scrollbar(table_container, orient="horizontal")

        tree = ttk.Treeview(
            table_container,
            columns=columns,
            show='headings',
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set
        )

        v_scroll.config(command=tree.yview)
        h_scroll.config(command=tree.xview)

        v_scroll.pack(side="right", fill="y")
        h_scroll.pack(side="bottom", fill="x")
        tree.pack(side="left", fill="both", expand=True)

        
        for col in columns:
            tree.heading(
            col,
            text=f" {col.upper()}",
            command=lambda c=col: sort_column_data(c)
                )    
            tree.column(col, anchor="w", width=150, minwidth=100, stretch=False)

        tree.tag_configure('oddrow', background='#f9f9f9')
        tree.tag_configure('evenrow', background='white')

        for row_index, row in enumerate(rows):
            processed_row = [
                cell if cell not in [None, 0, "None"] else '-'
                for cell in row
            ]
            tag = 'evenrow' if row_index % 2 == 0 else 'oddrow'
            tree.insert('', 'end', values=processed_row, tags=(tag,))

    # ---------------- NAVIGATION BAR ----------------
    nav_bar = tk.Frame(content_frame, bg=BG_MAIN)
    nav_bar.pack(fill="x", side="bottom", padx=30, pady=20)

    def create_nav_btn(parent, text, cmd, side):
        btn = tk.Button(
            parent,
            text=text,
            command=cmd,
            font=("Segoe UI", 9, "bold"),
            bg=CARD_BG,
            fg=ACCENT_BLUE,
            relief="flat",
            highlightbackground=ACCENT_BLUE,
            highlightthickness=1,
            padx=15,
            pady=5,
            cursor="hand2"
        )
        btn.pack(side=side, padx=5)
        return btn

    if end < total_rows:
        create_nav_btn(nav_bar, "Next Page →", next_page, "right")

    if current_page > 0:
        create_nav_btn(nav_bar, "← Previous Page", prev_page, "left")

    current_range = f"{start + 1}-{min(end, total_rows)}" if total_rows > 0 else "0-0"

    tk.Label(
        nav_bar,
        text=f"Page {current_page + 1}  |  Showing {current_range} of {total_rows}",
        font=("Segoe UI", 9),
        fg="#7f8c8d",
        bg=BG_MAIN
    ).pack(side="left", expand=True)




def sort_column_data(column_name):
    global all_rows

    col_index = columns.index(column_name)

    # Toggle sort direction
    if APP_STATE["sort_column"] == column_name:
        APP_STATE["sort_reverse"] = not APP_STATE["sort_reverse"]
    else:
        APP_STATE["sort_reverse"] = False

    APP_STATE["sort_column"] = column_name

    def sort_key(row):
        value = row[col_index]

        if value is None:
            return ""

        value_str = str(value).strip()

        # ---- IP ADDRESS SORT (IPv4 + IPv6 SAFE) ----
        try:
            ip_obj = ipaddress.ip_address(value_str)
            return (ip_obj.version, int(ip_obj))
        except ValueError:
            pass

        # ---- NUMBER SORT ----
        try:
            return float(value_str)
        except ValueError:
            pass

        # ---- DATETIME SORT ----
        try:
            return datetime.strptime(value_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

        # ---- DEFAULT STRING SORT ----
        return value_str.lower()

    all_rows.sort(
        key=sort_key,
        reverse=APP_STATE["sort_reverse"]
    )

    APP_STATE["current_page"] = 0
    show_page_data(preserve_state=True)




def next_page():
    global current_page
    current_page += 1
    show_page_data(preserve_state=True)

def prev_page():
    global current_page
    current_page -= 1
    show_page_data(preserve_state=True)


root.mainloop()





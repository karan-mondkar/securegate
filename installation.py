import os
import sys
import subprocess
import shutil
import requests
import importlib.util
import platform
from dotenv import load_dotenv

# ==================================================
# CONFIG
# ==================================================
import os
import time
import traceback


def get_current_directory():
    """
    Returns the directory where the installer (py or exe) is located.
    Works on Windows, Linux, Python, and PyInstaller EXE.
    """
    if getattr(sys, "frozen", False):
        # Running as EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as Python script
        return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_current_directory()
LOG_FILE = os.path.join(BASE_DIR, "securegate_error.log")

def log_error(message, exc=None):
    """
    Appends error message to securegate_error.log.
    File is created automatically if it does not exist.
    """
    try:
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






import sys
import sys
import datetime














ENV_FILE = os.path.join(BASE_DIR, "securegate.env")

# ==================================================
# ENV CONFIG (INSTALLER-ONLY)
# ==================================================

REQUIRED_ENV = {
    "SECUREGATE_BASE_DIR": BASE_DIR.replace("\\", "/"),
    "SECUREGATE_DB_HOST": "localhost",
    "SECUREGATE_DB_PORT": "3306",
    "SECUREGATE_DB_USER": "root",
    "SECUREGATE_DB_PASS": "",
    "SECUREGATE_DB_NAME": "securegate",

    "SECUREGATE_QUEUE_MAXSIZE": "500000",
    "SECUREGATE_PACKET_QUEUE_SIZE": "50000",
    "SECUREGATE_WHITELIST_REFRESH_INTERVAL": "5",

    "SECUREGATE_BLOCK_TIME_BUFFER_PERCENT": "10",

    "SECUREGATE_PORT_SCAN_THRESHOLD": "25",
    "SECUREGATE_HIGH_SEVERITY_PORTS": "100",
    "SECUREGATE_MIN_PACKETS": "50",
    "SECUREGATE_MASS_SCAN_PORTS": "1000",
    "SECUREGATE_SYN_RATIO_THRESHOLD": "0.4",

    "SECUREGATE_GEOIP_API": "http://ip-api.com/json",
    "SECUREGATE_INTERNET_TEST_IP": "8.8.8.8",
    "SECUREGATE_INTERNET_TEST_PORT": "53",

    "SECUREGATE_INTERFACE": "eth0",
    "SECUREGATE_LOG_COPY_INTERVAL": "3",
    "SECUREGATE_LOG_FILE_STAGE1": "securegate_detailed_log1.json",
    "SECUREGATE_LOG_FILE_STAGE2": "securegate_detailed_log2.json",
    "SECUREGATE_LOG_FILE_IMPORTANT": "imp_detailed_log.json",
    "SECUREGATE_KEY_FILE": "securegate.key",

    "SECUREGATE_GUI_REFRESH_INTERVAL": "10",
    "SECUREGATE_GUI_ROWS_PER_PAGE": "15",
    "SECUREGATE_GUI_WIDTH": "1100",
    "SECUREGATE_GUI_HEIGHT": "700",
    "SECUREGATE_GUI_ICON": "securegate_image.ico",
    "SECUREGATE_GUI_BANNER": "securegate_.png",
    "SECUREGATE_GUI_THEME": "arc"

}


def env(key, default=None, required=False, cast=None):
    val = os.getenv(key)

    if val is None or val.strip() == "":
        if required:
            raise RuntimeError(f"Missing required env variable: {key}")
        return default

    val = val.strip()

    if cast:
        try:
            return cast(val)
        except Exception as e:
            log_error("Engine crashed during startup", e)    
            raise RuntimeError(f"Invalid value for {key}: {val}")

    return val


def build_db_config(allow_no_db=False):
    cfg = {
        "host": env("SECUREGATE_DB_HOST", "127.0.0.1"),
        "user": env("SECUREGATE_DB_USER", "root"),
        "password": env("SECUREGATE_DB_PASS", ""),
        "port": env("SECUREGATE_DB_PORT", 3306, cast=int),
        "connection_timeout": 3,
        "autocommit": True,
        "use_pure": True,
    }

    if not allow_no_db:
        cfg["database"] = env("SECUREGATE_DB_NAME", required=True)

    return cfg


def create_env_file_once():
    # If env already exists, DO NOTHING
    if os.path.exists(ENV_FILE):
        print("✔ securegate.env already exists")
        return

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write("# SecureGate Environment Configuration\n")
        f.write("# Auto-generated during first installation\n\n")

        for k, v in REQUIRED_ENV.items():
            # Normalize paths for cross-platform safety
            if k == "SECUREGATE_BASE_DIR":
                v = str(v).replace("\\", "/")
            else:
                v = str(v)

            f.write(f"{k}={v}\n")

    print("✅ securegate.env created")
    print("⚠️  Review the file and re-run installer")
    
def validate_env_file_or_exit():
    load_dotenv(ENV_FILE)

    errors = []

    for key in REQUIRED_ENV:
        val = os.getenv(key)

        if val is None or (val.strip() == "" and key != "SECUREGATE_DB_PASS"):
            errors.append(f"Missing or empty: {key}")

        if key.endswith("_PORT") or "SIZE" in key or "INTERVAL" in key:
            if val and not val.isdigit():
                errors.append(f"Invalid integer: {key}={val}")

        if key == "SECUREGATE_SYN_RATIO_THRESHOLD":
            try:
                float(val)
            except Exception as e:
                log_error("Engine crashed during startup", e)
                errors.append(f"Invalid float: {key}={val}")

    if errors:
        print("\n❌ Configuration errors:\n")
        for e in errors:
            print("  •", e)
        print("\n🛑 Fix securegate.env and re-run installer\n")
        sys.exit(1)

    print("✔ securegate.env validated\n")

def ensure_env_ready():
    if not os.path.exists(ENV_FILE):
        create_env_file_once()
    validate_env_file_or_exit()
    confirm_env_or_exit()


# ==================================================
# ENV FILE REVIEW (USER CONFIRMATION)
# ==================================================

def open_env_file_for_edit():
    print("\n📝 Opening securegate.env for review/editing...\n")

    try:
        if platform.system() == "Windows":
            os.startfile(ENV_FILE)
        elif platform.system() == "Linux":
            subprocess.call(["nano", ENV_FILE])
        else:
            print(f"📄 Please edit manually: {ENV_FILE}")
    except Exception as e:
        log_error("Engine crashed during startup", e)
        print(f"📄 Please edit manually: {ENV_FILE}")

def confirm_env_or_exit():
    open_env_file_for_edit()

    answer = input("\n❓ Is the configuration correct? (yes/no): ").strip().lower()
    if answer not in ("yes", "y"):
        print("\n🛑 Installation aborted.")
        print("👉 Fix securegate.env and re-run installer.\n")
        sys.exit(0)

    # 🔁 RELOAD ENV AFTER USER MODIFICATION (CRITICAL FIX)
    load_dotenv(ENV_FILE, override=True)

    # 🔍 Re-validate with UPDATED values
    validate_env_file_or_exit()

    print("✔ Configuration confirmed and reloaded\n")


# ==================================================
# DEPENDENCY CHECK
# ==================================================

LIBRARIES = {
    "mysql.connector": "mysql-connector-python",
    "requests": "requests",
    "scapy": "scapy",
    "portalocker": "portalocker",
    "matplotlib": "matplotlib",
    "bcrypt": "bcrypt",
    "psutil": "psutil",
    "PIL": "Pillow",
    "dotenv": "python-dotenv"
}

import os
import sys

# Force the working directory to the script's actual location



def module_installed(name):
    return importlib.util.find_spec(name) is not None

def install_package(pkg):
    print(f"⬇ Installing {pkg}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
    except subprocess.CalledProcessError as e:
        log_error("Engine crashed during startup", e)
        
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages", pkg
        ])

def ensure_dependencies():
    print("\n🔍 Checking Python dependencies\n")
    for module, pkg in LIBRARIES.items():
        if module_installed(module):
            print(f"✔ {pkg}")
        else:
            print(f"❌ {pkg}")
            install_package(pkg)
    print("\n✔ All dependencies ready\n")

# ==================================================
# DOWNLOAD FILES
# ==================================================

FILES = {
    "gui.py": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/gui.py",
    "securegate_new.py": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_new.py",
    "network_monitor.py": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/network_monitor.py",
    "securegate_image.ico": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_image.ico"
}

def download_files():
    print("⬇ Downloading SecureGate files\n")

    for name, url in FILES.items():
        path = os.path.join(BASE_DIR, name)
        if os.path.exists(path):
            print(f"✔ {name} already exists")
            continue

        r = requests.get(url, stream=True)
        if r.status_code == 200:
            with open(path, "wb") as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            print(f"⬇ Downloaded {name}")
        else:
            print(f"❌ Failed to download {name}")
            sys.exit(1)

# ==================================================
# MYSQL CHECK
# ==================================================
import mysql.connector
import time
# ==================================================
# UNICODE FIX (ADD THIS)
# ==================================================
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


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

# ==================================================
# SERVICES
# ==================================================

def create_linux_service(name, script):
    service_path = f"/etc/systemd/system/{name}.service"
    if os.path.exists(service_path):
        print(f"✔ {name} service exists")
        return

    python = sys.executable
    content = f"""[Unit]
Description=SecureGate {name}
After=network.target mysql.service

[Service]
ExecStart={python} {script}
Restart=always
RestartSec=5
WorkingDirectory={BASE_DIR}
User=root

[Install]
WantedBy=multi-user.target
"""

    with open(service_path, "w") as f:
        f.write(content)

    subprocess.call(["systemctl", "daemon-reload"])
    subprocess.call(["systemctl", "enable", name])
    subprocess.call(["systemctl", "start", name])

    print(f"✔ Created service: {name}")
    
    



import subprocess
import sys
import os


ENGINE_SERVICE = "securegate-engine"
MONITOR_SERVICE = "securegate-monitor"

ENGINE_SCRIPT = os.path.join(BASE_DIR, "securegate_new.py")
MONITOR_SCRIPT = os.path.join(BASE_DIR, "network_monitor.py")

def ensure_services():
    os_name = platform.system()
    
    if os_name == "Linux":
        create_linux_service(ENGINE_SERVICE, ENGINE_SCRIPT)
        create_linux_service(MONITOR_SERVICE, MONITOR_SCRIPT)

    elif os_name == "Windows":
        pass
        # Pass the global script paths defined at the top
        # Change the task_run line to this to catch errors:
        #create_windows_service(ENGINE_SERVICE, ENGINE_SCRIPT)
        #create_windows_service(MONITOR_SERVICE, MONITOR_SCRIPT)
# ==================================================
# GUI
# ==================================================

# ==================================================
# MAIN
# ==================================================

def main():
    ensure_dependencies()
    download_files()
    ensure_env_ready()
    ensure_mysql_ready_or_exit()
    ensure_services()
    print("\n✅ SecureGate fully operational\n")

if __name__ == "__main__":
    try:
        print("🚀 Starting SecureGate installer...\n")
        main()
    except Exception as e:
        log_error("Installer crashed", e)
        print("❌ Installer failed. Check securegate_error.log")
        sys.exit(1)

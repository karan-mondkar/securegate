import os
import sys
import subprocess
import shutil
import requests
import importlib.util
import platform

# ==================================================
# CONFIG
# ==================================================

BASE_DIR = os.path.abspath("securegate_files")

ENGINE_SCRIPT = os.path.join(BASE_DIR, "securegate_new.py")
MONITOR_SCRIPT = os.path.join(BASE_DIR, "network_monitor.py")
GUI_SCRIPT = os.path.join(BASE_DIR, "gui.py")

ENGINE_SERVICE = "securegate-engine"
MONITOR_SERVICE = "securegate-monitor"

# ==================================================
# 1. DEPENDENCY CHECK
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
}

def module_installed(name):
    return importlib.util.find_spec(name) is not None

def install_package(pkg):
    print(f"⬇ Installing {pkg}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
    except subprocess.CalledProcessError:
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
# 2. DOWNLOAD FILES
# ==================================================

FILES = {
    "gui.py": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/gui.py",
    "securegate_new.py": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_new.py",
    "network_monitor.py": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/network_monitor.py",
    "securegate_image.ico": "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_image.ico"
}

def download_files():
    os.makedirs(BASE_DIR, exist_ok=True)
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
# 3. MYSQL CHECK
# ==================================================
def ensure_mysql_ready_or_exit():
    print("\n🔍 Checking MySQL service (OS-level)\n")
    system = platform.system()

    def run(cmd):
        return subprocess.call(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ) == 0

    if system == "Linux":
        # MySQL may be mysql or mariadb
        if run(["systemctl", "is-active", "--quiet", "mysql"]) or \
           run(["systemctl", "is-active", "--quiet", "mariadb"]):
            print("✔ MySQL/MariaDB service is running")
            return

        print("⚠ MySQL not running. Attempting to start...")
        if run(["systemctl", "start", "mysql"]) or \
           run(["systemctl", "start", "mariadb"]):
            print("✔ MySQL service started")
            return

        print("❌ MySQL service failed to start")
        sys.exit(1)

    elif system == "Windows":
        # Windows service name varies: MySQL, MySQL80, etc.
        result = subprocess.check_output(
            ["sc", "query"],
            stderr=subprocess.DEVNULL,
            text=True
        )

        mysql_services = [line.split()[0] for line in result.splitlines()
                          if "MySQL" in line]

        if not mysql_services:
            print("❌ No MySQL service found on system")
            sys.exit(1)

        for svc in mysql_services:
            if run(["sc", "query", svc]):
                run(["net", "start", svc])
                print(f"✔ MySQL service running: {svc}")
                return

        print("❌ MySQL service exists but could not be started")
        sys.exit(1)

# ==================================================
# 4. SERVICES (LINUX)
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

    subprocess.check_call(["systemctl", "daemon-reload"])
    subprocess.check_call(["systemctl", "enable", name])
    subprocess.check_call(["systemctl", "start", name])

    print(f"✔ Created Linux service: {name}")

# ==================================================
# 5. SERVICES (WINDOWS)
# ==================================================

def create_windows_service(name, script):
    python = sys.executable
    cmd = f'"{python}" "{script}"'

    exists = subprocess.call(
        ["sc", "query", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0

    if exists:
        print(f"✔ {name} service exists")
        return

    subprocess.check_call([
        "sc", "create", name,
        "binPath=", cmd,
        "start=", "auto"
    ])
    subprocess.check_call(["sc", "start", name])

    print(f"✔ Created Windows service: {name}")

# ==================================================
# 6. ENSURE SERVICES RUNNING
# ==================================================

def ensure_services():
    print("\n⚙ Ensuring SecureGate services\n")
    system = platform.system()

    if system == "Linux":
        create_linux_service(ENGINE_SERVICE, ENGINE_SCRIPT)
        create_linux_service(MONITOR_SERVICE, MONITOR_SCRIPT)

    elif system == "Windows":
        create_windows_service(ENGINE_SERVICE, ENGINE_SCRIPT)
        create_windows_service(MONITOR_SERVICE, MONITOR_SCRIPT)

# ==================================================
# 7. LAUNCH GUI
# ==================================================

def launch_gui():
    print("\n🖥 Launching SecureGate GUI\n")
    system = platform.system()

    if system == "Windows":
        subprocess.Popen(["cmd", "/k", sys.executable, GUI_SCRIPT])
    else:
        if not shutil.which("xterm"):
            subprocess.check_call(["apt", "install", "-y", "xterm"])
        subprocess.Popen(["xterm", "-hold", "-e", f"{sys.executable} {GUI_SCRIPT}"])

# ==================================================
# MAIN
# ==================================================

def main():
    ensure_dependencies()
    download_files()
    ensure_mysql_ready_or_exit()
    ensure_services()
    launch_gui()
    print("\n✅ SecureGate fully operational\n")

if __name__ == "__main__":
    main()

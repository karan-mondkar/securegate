import os
import sys
import subprocess
import platform
import time
from dotenv import load_dotenv

# ==================================================
# CONFIG
# ==================================================

ENGINE_SERVICE = "securegate-engine"
MONITOR_SERVICE = "securegate-monitor"

BASE_DIR = os.path.abspath("securegate_files")
ENV_FILE = os.path.join(BASE_DIR, "securegate.env")

SECUREGATE_DB_NAME = "securegate"   # ONLY this DB can be deleted

# ==================================================
# LOAD ENV (SAFE)
# ==================================================

if os.path.exists(ENV_FILE):
    load_dotenv(ENV_FILE)

DB_HOST = os.getenv("SECUREGATE_DB_HOST", "127.0.0.1")
DB_USER = os.getenv("SECUREGATE_DB_USER", "root")
DB_PASS = os.getenv("SECUREGATE_DB_PASS", "")
DB_PORT = int(os.getenv("SECUREGATE_DB_PORT", "3306"))

# ==================================================
# UTILS
# ==================================================

def run(cmd, shell=False):
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=shell)
        return True
    except subprocess.CalledProcessError:
        return False

def run_output(cmd, shell=False):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, shell=shell)
    except Exception:
        return ""

# ==================================================
# 1. STOP SECUREGATE SERVICES
# ==================================================

def stop_securegate_services():
    print("\n🛑 Stopping SecureGate services")
    system = platform.system()

    if system == "Linux":
        run(["systemctl", "stop", ENGINE_SERVICE])
        run(["systemctl", "stop", MONITOR_SERVICE])

    elif system == "Windows":
        run(["sc", "stop", ENGINE_SERVICE], shell=True)
        run(["sc", "stop", MONITOR_SERVICE], shell=True)

    print("✔ SecureGate services stopped")

# ==================================================
# 2. KILL ONLY SECUREGATE PYTHON PROCESSES
# ==================================================

def kill_securegate_processes():
    print("\n💀 Killing SecureGate Python processes")
    system = platform.system()

    if system == "Linux":
        run(["pkill", "-f", "securegate_new.py"])
        run(["pkill", "-f", "network_monitor.py"])
        run(["pkill", "-f", "gui.py"])

    elif system == "Windows":
        scripts = ["securegate_new.py", "network_monitor.py", "gui.py"]
        for script in scripts:
            run(
                f'taskkill /F /IM python.exe /FI "WINDOWTITLE eq *{script}*"',
                shell=True
            )

    print("✔ SecureGate processes terminated")

# ==================================================
# 3. DISABLE & DELETE SERVICES
# ==================================================

def delete_securegate_services():
    print("\n🧹 Removing SecureGate services")
    system = platform.system()

    if system == "Linux":
        run(["systemctl", "disable", ENGINE_SERVICE])
        run(["systemctl", "disable", MONITOR_SERVICE])

        for svc in (
            f"/etc/systemd/system/{ENGINE_SERVICE}.service",
            f"/etc/systemd/system/{MONITOR_SERVICE}.service"
        ):
            if os.path.exists(svc):
                os.remove(svc)

        run(["systemctl", "daemon-reload"])

    elif system == "Windows":
        run(["sc", "delete", ENGINE_SERVICE], shell=True)
        run(["sc", "delete", MONITOR_SERVICE], shell=True)

    print("✔ SecureGate services removed")

# ==================================================
# 4. STOP MYSQL SERVICE (SAFE)
# ==================================================

def stop_mysql_service():
    print("\n🛑 Stopping MySQL service")
    system = platform.system()

    if system == "Linux":
        run(["systemctl", "stop", "mysql"])
        run(["systemctl", "stop", "mariadb"])

    elif system == "Windows":
        output = run_output('sc query state= all | findstr /I "MySQL MariaDB"', shell=True)
        for line in output.splitlines():
            if "SERVICE_NAME" in line:
                svc = line.split(":")[1].strip()
                run(["net", "stop", svc], shell=True)

    print("✔ MySQL service stopped (if it was running)")

# ==================================================
# 5. ASK BEFORE DELETING DATABASE
# ==================================================

def confirm_database_deletion():
    print("\n⚠ DATABASE DELETION WARNING ⚠")
    print(f"This will permanently delete the database: {SECUREGATE_DB_NAME}")
    answer = input("Do you want to delete the database? (yes/no): ").strip().lower()
    return answer in ("yes", "y")

def delete_securegate_database():
    print("\n🗑 Deleting SecureGate database")

    try:
        import mysql.connector

        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT
        )

        cursor = conn.cursor()
        cursor.execute(f"DROP DATABASE IF EXISTS `{SECUREGATE_DB_NAME}`")
        conn.commit()

        cursor.close()
        conn.close()

        print(f"✔ Database '{SECUREGATE_DB_NAME}' deleted")

    except Exception as e:
        print("⚠ Could not delete database")
        print("   Reason:", e)
        print("   (This is OK if credentials differ or DB was remote)")

# ==================================================
# MAIN
# ==================================================

def main():
    print("\n🔥 SECUREGATE CLEANUP STARTED 🔥\n")

    stop_securegate_services()
    time.sleep(1)

    kill_securegate_processes()
    time.sleep(1)

    delete_securegate_services()
    time.sleep(1)

    stop_mysql_service()
    time.sleep(1)

    if confirm_database_deletion():
        delete_securegate_database()
    else:
        print("\nℹ Database preserved (no data deleted)")

    print("\n✅ SecureGate cleanup completed")
    print("👉 You can now test fresh bootstrap safely\n")

if __name__ == "__main__":
    main()

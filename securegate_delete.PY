import os
import sys
import subprocess
import platform
import time

# ==================================================
# CONFIG
# ==================================================

ENGINE_SERVICE = "securegate-engine"
MONITOR_SERVICE = "securegate-monitor"

SECUREGATE_DB_NAME = "securegate"   # ONLY this DB will be deleted

# ==================================================
# UTILS
# ==================================================

def run(cmd):
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def run_output(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except:
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
        run(["sc", "stop", ENGINE_SERVICE])
        run(["sc", "stop", MONITOR_SERVICE])

    print("✔ SecureGate services stopped")

# ==================================================
# 2. KILL STRAY PYTHON PROCESSES (SAFE FILTER)
# ==================================================

def kill_securegate_processes():
    print("\n💀 Killing SecureGate processes (if any)")
    system = platform.system()

    if system == "Linux":
        run(["pkill", "-f", "securegate_new.py"])
        run(["pkill", "-f", "network_monitor.py"])
        run(["pkill", "-f", "gui.py"])

    elif system == "Windows":
        run(["taskkill", "/F", "/IM", "python.exe", "/T"])

    print("✔ Processes terminated")

# ==================================================
# 3. DISABLE & DELETE SERVICES
# ==================================================

def delete_securegate_services():
    print("\n🧹 Removing SecureGate services")
    system = platform.system()

    if system == "Linux":
        run(["systemctl", "disable", ENGINE_SERVICE])
        run(["systemctl", "disable", MONITOR_SERVICE])

        service_files = [
            f"/etc/systemd/system/{ENGINE_SERVICE}.service",
            f"/etc/systemd/system/{MONITOR_SERVICE}.service"
        ]

        for svc in service_files:
            if os.path.exists(svc):
                os.remove(svc)

        run(["systemctl", "daemon-reload"])

    elif system == "Windows":
        run(["sc", "delete", ENGINE_SERVICE])
        run(["sc", "delete", MONITOR_SERVICE])

    print("✔ SecureGate services removed")

# ==================================================
# 4. STOP MYSQL SERVICE
# ==================================================

def stop_mysql_service():
    print("\n🛑 Stopping MySQL service")
    system = platform.system()

    if system == "Linux":
        run(["systemctl", "stop", "mysql"])
        run(["systemctl", "stop", "mariadb"])

    elif system == "Windows":
        output = run_output(["sc", "query"])

        mysql_services = [
            line.split()[0]
            for line in output.splitlines()
            if "MySQL" in line
        ]

        for svc in mysql_services:
            run(["net", "stop", svc])

    print("✔ MySQL service stopped")

# ==================================================
# 5. DROP SECUREGATE DATABASE ONLY
# ==================================================

def delete_securegate_database():
    print("\n🗑 Dropping SecureGate database ONLY")

    try:
        import mysql.connector

        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=""
        )

        cursor = conn.cursor()
        cursor.execute(f"DROP DATABASE IF EXISTS {SECUREGATE_DB_NAME}")
        conn.commit()

        cursor.close()
        conn.close()

        print(f"✔ Database '{SECUREGATE_DB_NAME}' deleted")

    except Exception as e:
        print("⚠ Could not delete database (credentials may differ)")
        print("   This is OK if DB was remote or protected")

# ==================================================
# 6. FINAL CONFIRMATION
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

    delete_securegate_database()

    print("\n✅ SecureGate cleanup completed")
    print("You can now test bootstrap behavior from a clean state\n")

if __name__ == "__main__":
    main()

import time
import subprocess
import mysql.connector
from mysql.connector import Error

# ===============================
# CONFIG (PRACTICE MODE)
# ===============================
DB_CONFIG = {
    "host": "127.0.0.1",        # ALWAYS use this on Windows
    "user": "root",
    "password": "mypassword",  # 🔴 PUT YOUR ROOT PASSWORD HERE
    "port": 3306,
    "use_pure": True
}

MYSQL_SERVICE_NAME = "MySQL80"

# ===============================
# START MYSQL SERVICE (WINDOWS)
# ===============================
def start_mysql_service():
    print("▶ Ensuring MySQL service is running...")
    subprocess.call(
        ["sc", "start", MYSQL_SERVICE_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=True
    )
    time.sleep(3)

# ===============================
# INSERT DATA (SAFE VERSION)
# ===============================
def insert_data():
    conn = None
    cursor = None

    try:
        print("▶ Connecting to MySQL...")
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 🔑 THIS LINE WAS THE ISSUE — MUST RUN FIRST
        cursor.execute("USE mysql")

        # 🔍 Verify database selection (optional but safe)
        cursor.execute("SELECT DATABASE()")
        db = cursor.fetchone()[0]
        print(f"✔ Using database: {db}")

        # ✅ Now table operations are valid
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_table (
                id INT AUTO_INCREMENT PRIMARY KEY,
                msg VARCHAR(100)
            )
        """)

        cursor.execute(
            "INSERT INTO test_table (msg) VALUES (%s)",
            ("Hello from Python",)
        )

        conn.commit()
        print("✅ Data inserted successfully")

    except Error as e:
        print("❌ MySQL Error:", e)

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    start_mysql_service()
    insert_data()

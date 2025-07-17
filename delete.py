import os
import mysql.connector

# ---------- Step 1: Drop the securegate database ----------
try:
    # Connect to MySQL (update with your credentials if needed)
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password=""  # Replace with your actual MySQL root password
    )
    cursor = conn.cursor()
    
    # Drop the database
    cursor.execute("DROP DATABASE IF EXISTS securegate")
    print("Database 'securegate' dropped successfully.")

    cursor.close()
    conn.close()

except mysql.connector.Error as err:
    print(f"Error dropping database: {err}")

# ---------- Step 2: Delete log files ----------
files_to_delete = [
    "securegate_detailed_log1.json",
    "securegate_detailed_log2.json",
    "imp_detailed_log.json"
]

for file in files_to_delete:
    try:
        if os.path.exists(file):
            os.remove(file)
            print(f"Deleted file: {file}")
        else:
            print(f"File not found: {file}")
    except Exception as e:
        print(f"Error deleting {file}: {e}")

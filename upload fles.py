import mysql.connector
import subprocess
import os

# Full absolute path of rclone.exe (your path)
RCLONE_PATH = r"C:\Users\karan\Downloads\rclone-v1.71.2-windows-amd64\rclone-v1.71.2-windows-amd64\rclone.exe"



def open_rclone_config():
    rclone_path = r"C:\Users\karan\Downloads\rclone-v1.71.2-windows-amd64\rclone-v1.71.2-windows-amd64\rclone.exe"
    cmd = f'"{rclone_path}" config'
    
    subprocess.run(cmd, shell=True)

#open_rclone_config()
def upload_sensitive_files_to_drive():

    # ---------------------------
    # 1. Connect to MySQL
    # ---------------------------
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            port=3306,
            database="securegate"
        )

        cursor = connection.cursor(buffered=True)
        cursor.execute("SELECT upload_folder, sensitive_folders FROM settings LIMIT 1")
        result = cursor.fetchone()
        cursor.close()
        connection.close()

    except Exception as e:
        print(f"[DB ERROR] {e}")
        return

    # ---------------------------
    # 2. Validate database result
    # ---------------------------
    if not result:
        print("[!] No folder paths found in database.")
        return

    upload_folder, sensitive_folder = result

    print("Upload Location :", upload_folder)
    print("Sensitive Folder:", sensitive_folder)

    if not upload_folder or not sensitive_folder:
        print("[!] Upload or sensitive folder is missing in DB.")
        return

    # ---------------------------
    # 3. Ensure rclone.exe exists
    # ---------------------------
    if not os.path.exists(RCLONE_PATH):
        print(f"[ERROR] rclone not found at: {RCLONE_PATH}")
        return

    # ---------------------------
    # 4. Build rclone command
    # ---------------------------
    cmd = f'"{RCLONE_PATH}" copy "{sensitive_folder}" "{upload_folder}"'

    print("Running Command:")
    print(cmd)

    # ---------------------------
    # 5. Execute command
    # ---------------------------
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True  # required for Windows
        )

        if result.returncode == 0:
            print("[UPLOAD SUCCESS] Sensitive folder uploaded.")
        else:
            print("[UPLOAD ERROR]", result.stderr)

    except Exception as e:
        print("[EXCEPTION]", e)
#open_rclone_config()
upload_sensitive_files_to_drive()

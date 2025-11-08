import os
import subprocess
import shutil
import requests
import importlib.util

libraries = {
    "os": "os",
    "json": "json",
    "time": "time",
    "datetime": "datetime",
    "socket": "socket",
    "smtplib": "smtplib",
    "tkinter": "tkinter",
    "mysql.connector": "mysql-connector-python",
    "requests": "requests",
    "scapy.all": "scapy",
    "portalocker": "portalocker",
    "matplotlib": "matplotlib",
    "bcrypt": "bcrypt",
    "scipy": "scipy",
    "psutil":"psutil",
    "PIL":"PIL"
}

def is_module_installed(module_name):
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False

print(" Checking/installing required libraries...\n")
for module, pip_name in libraries.items():
    if is_module_installed(module):
        print(f" {pip_name} already installed.")
    else:
        print(f"️ Installing {pip_name}...")
        try:
            subprocess.check_call(["python3", "-m", "pip", "install", pip_name])
        except Exception:
            try:
                subprocess.check_call(["python", "-m", "pip", "install", pip_name])
            except Exception as e:
                print(f"️ Could not install {pip_name}: {e}")

print("\n Library check complete.\n")

def download_file(url, save_dir="securegate_files", filename=None):
    os.makedirs(save_dir, exist_ok=True)

    if not filename:
        filename = url.split("/")[-1]

    filepath = os.path.join(save_dir, filename)

    if os.path.exists(filepath):
        print(f"️ Already exists: {filepath} — skipping download")
        return

    if "github.com" in url and "blob" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob", "")

    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(filepath, "wb") as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"Downloaded: {filepath}")
    else:
        print(f"Failed to download {url}. Status code: {response.status_code}")

urls = [
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/gui.py",
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/network_monitor.py",
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_new.py",
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_image.ico"
]

for url in urls:
    download_file(url)

python_cmd = shutil.which("python3") or shutil.which("python")
if not python_cmd:
    raise RuntimeError(" No Python interpreter found!")

project_files = [
    
    "securegate_files/network_monitor.py",
    "securegate_files/securegate_new.py",
    "securegate_files/gui.py"
]

processes = []

print("\n Starting SecureGate scripts in parallel...\n")
for script in project_files:
    if os.path.exists(script):
        print(f" Launching: {script}")
        p = subprocess.Popen([python_cmd, script])
        processes.append(p)
    else:
        print(f" File not found: {script}")

print("\n✅ All SecureGate scripts have finished .")

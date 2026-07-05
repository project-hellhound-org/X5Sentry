#!/bin/bash
# install.sh — High-Fidelity Setup for xssentry v4.0 [HELLHOUND-class]

# Zero-dependency Python HUD for immediate animation start
python3 - << 'EOF'
import sys
import time
import math
import threading
import subprocess
import shutil
import os

# ------ CONFIGURATION & ASSETS ------
_BRAILLE_WAVE = ["⠁", "⠃", "⠇", "⡇", "⣇", "⣧", "⣷", "⣿", "⣾", "⣶", "⣦", "⣄", "⡄", "⠄", "⠀", "⠀"]

def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def case_wave_ansi(text, frame):
    """Simple ANSI-based case-wave effect."""
    result = ""
    for i, ch in enumerate(text):
        if ch == " ":
            result += " "
            continue
        val = math.sin(i * 0.45 + frame * 4.5)
        if val > 0.7:
            result += f"\033[1;31m{ch.upper()}\033[0m"
        elif val > 0.3:
            result += f"\033[31m{ch.upper()}\033[0m"
        elif val > -0.1:
            result += f"\033[31m{ch}\033[0m"
        else:
            result += f"\033[2;31m{ch.lower()}\033[0m"
    return result

def draw_ui(text, stop_event):
    """Animates a single-line HUD using pure ANSI (Zero Dependencies)."""
    n = len(_BRAILLE_WAVE)
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()
    try:
        while not stop_event.is_set():
            t = time.time()
            tw = get_terminal_width()
            txt = case_wave_ansi(text, t)
            wave_width = (tw - len(text) - 10) // 2
            if wave_width < 2:
                sys.stdout.write(f"\r{txt}")
            else:
                left_chars = "".join(_BRAILLE_WAVE[int((i * 1.5 - t * 18)) % n] for i in range(wave_width))
                right_chars = "".join(_BRAILLE_WAVE[int(((wave_width - i) * 1.5 + t * 18)) % n] for i in range(wave_width))
                sys.stdout.write(f"\r\033[1;31m{left_chars}\033[0m  {txt}  \033[1;31m{right_chars}\033[0m")
            sys.stdout.flush()
            time.sleep(0.04)
    finally:
        sys.stdout.write("\r\033[K\033[?25h")
        sys.stdout.flush()

def run_task(text, cmd, capture=True):
    """Runs a task with the immediate animation."""
    stop_event = threading.Event()
    t = threading.Thread(target=draw_ui, args=(text, stop_event), daemon=True)
    t.start()
    try:
        if capture:
            subprocess.run(cmd, shell=True, capture_output=True)
        else:
            subprocess.run(cmd, shell=True)
    finally:
        stop_event.set()
        t.join()

def main():
    if os.getuid() != 0:
        print("[*] Authenticating sudo privileges (credentials will be cached)...")
        try:
            subprocess.run("sudo -v", shell=True, check=True)
        except subprocess.CalledProcessError:
            print("[-] Sudo validation failed. Exiting.")
            sys.exit(1)

    if not os.path.exists(".venv"):
        run_task("INITIALIZING VIRTUAL ENVIRONMENT", "python3 -m venv .venv")
    run_task("OPTIMIZING DEPENDENCIES", "./.venv/bin/pip install --upgrade pip rich aiohttp beautifulsoup4 lxml playwright")
    run_task("INSTALLING BROWSER CORES", "./.venv/bin/python3 -m playwright install chromium")
    run_task("PATCHING SYSTEM LIBS", "sudo ./.venv/bin/python3 -m playwright install-deps chromium")
    run_task("FINALIZING SYSTEM SETUP", "./.venv/bin/pip install -e .")

    # Deploy global CLI wrapper — write a real script to /usr/local/bin/xssentry
    # Must rm first: old installs left a symlink pointing to the xssentry/ package
    # directory. sudo tee on a symlink-to-dir writes INSIDE the dir, not over it.
    project_root = os.path.abspath(os.getcwd())
    venv_python  = os.path.join(project_root, ".venv", "bin", "python3")
    entry_script = os.path.join(project_root, "xssentry_run.py")
    wrapper = f'#!/bin/bash\nexec "{venv_python}" "{entry_script}" "$@"\n'
    try:
        # 1) Remove old symlink/file — critical to avoid writing into directory
        subprocess.run(["sudo", "rm", "-f", "/usr/local/bin/xssentry"],
                       capture_output=True, check=True)
        # 2) Write fresh wrapper script
        subprocess.run(["sudo", "tee", "/usr/local/bin/xssentry"],
                       input=wrapper.encode(), capture_output=True, check=True)
        # 3) Make executable
        subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/xssentry"],
                       capture_output=True, check=True)
        print("\r\033[K\033[1;32m[+]\033[0m Global command deployed: /usr/local/bin/xssentry")
    except Exception as e:
        print(f"\r\033[K\033[31m[-]\033[0m Failed to deploy global link: {e}")

    print("\n\033[1;32m[+] X5SENTRY DEPLOYED SUCCESSFULLY\033[0m")
    print("\033[2mVERSION: 4.0.0-STABLE\033[0m\n")

if __name__ == "__main__":
    main()
EOF

import tkinter as tk
from tkinter import messagebox, ttk
import psutil
import subprocess
import socket
import os
import time
import requests
import shutil
import tempfile
import glob
import shlex
from pathlib import Path


APP_DIR = os.path.dirname(os.path.abspath(__file__))


TERMINAL_CANDIDATES = (
    ("gnome-terminal", ["--", "bash", "-lc"]),
    ("kgx", ["--", "bash", "-lc"]),
    ("x-terminal-emulator", ["-e", "bash", "-lc"]),
    ("konsole", ["-e", "bash", "-lc"]),
    ("xfce4-terminal", ["-e", "bash", "-lc"]),
    ("mate-terminal", ["-e", "bash", "-lc"]),
    ("lxterminal", ["-e", "bash", "-lc"]),
    ("tilix", ["-e", "bash", "-lc"]),
    ("alacritty", ["-e", "bash", "-lc"]),
    ("kitty", ["-e", "bash", "-lc"]),
)


def build_terminal_command(command: str, hold_open: bool = False):
    """Return the command list to launch *command* in an available terminal."""

    for terminal, args in TERMINAL_CANDIDATES:
        if shutil.which(terminal):
            suffix = "; echo 'Press Enter to close...'; read" if hold_open else ""
            full_command = f"{command}{suffix}"
            return [terminal, *args, full_command]

    raise FileNotFoundError(
        "No supported terminal emulator found. Install gnome-terminal, x-terminal-emulator, or another supported terminal."
    )


def open_terminal(command: str, hold_open: bool = False):
    """Launch *command* inside a graphical terminal emulator."""

    term_command = build_terminal_command(command, hold_open=hold_open)
    return subprocess.Popen(term_command)


def get_internal_ip():
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return addr.address
    except Exception:
        pass
    return "Unavailable"


def get_external_ip():
    try:
        response = requests.get("https://api.ipify.org", timeout=2)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return "Unavailable"


def detect_pwm_paths():
    pwm_paths = []
    for path in glob.glob("/sys/class/hwmon/hwmon*/pwm*"):
        if os.path.isfile(path):
            pwm_paths.append(path)
    return sorted(pwm_paths)


def run_program(command: str):
    try:
        subprocess.Popen(shlex.split(command))
    except FileNotFoundError:
        messagebox.showerror("Error", f"Command not found: {command.split()[0]}")
    except Exception as exc:
        messagebox.showerror("Error", f"Failed to launch command: {exc}")


def run_terminal_task(command: str, hold_open: bool = True):
    try:
        open_terminal(command, hold_open=hold_open)
    except FileNotFoundError as exc:
        messagebox.showerror("Terminal Error", str(exc))
    except Exception as exc:
        messagebox.showerror("Terminal Error", f"Failed to open terminal: {exc}")


def program_launcher(command: str):
    return lambda command=command: run_program(command)


def terminal_launcher(command: str, hold_open: bool = True):
    return lambda command=command, hold_open=hold_open: run_terminal_task(command, hold_open=hold_open)

def check_dependencies():
    missing = []

    for label, executables in DEPENDENCY_MAP.items():
        unavailable = [exe for exe in executables if not shutil.which(exe)]
        if unavailable:
            missing.append(f"{label} ({', '.join(unavailable)})")

    if missing:
        messagebox.showwarning(
            "Missing Tools",
            "Some tools are unavailable because their executables were not found:\n" + "\n".join(missing),
        )

def update_system_stats():
    cpu_usage = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')

    uptime_seconds = time.time() - psutil.boot_time()
    uptime_str = time.strftime('%H:%M:%S', time.gmtime(uptime_seconds))

    internal_ip = get_internal_ip()
    external_ip = get_external_ip()

    try:
        temps = psutil.sensors_temperatures()
    except (AttributeError, psutil.Error):
        temps = {}

    if temps:
        coretemp = temps.get("coretemp") or next((values for name, values in temps.items() if values), None)
        if coretemp:
            temp_label.config(text=f"CPU Temp: {coretemp[0].current:.1f}°C")
        else:
            temp_label.config(text="CPU Temp: N/A")
    else:
        temp_label.config(text="CPU Temp: Unavailable")

    cpu_label.config(text=f"CPU Usage: {cpu_usage}%")
    memory_label.config(text=f"Memory: {memory.percent}%")
    swap_label.config(text=f"Swap: {swap.percent}%")
    disk_label.config(text=f"Disk: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)")
    uptime_label.config(text=f"Uptime: {uptime_str}")
    internal_ip_label.config(text=f"Internal IP: {internal_ip}")
    external_ip_label.config(text=f"External IP: {external_ip}")
    
    # Update fan speed
    sensor_data = get_sensors_data()
    fan_speeds = sensor_data.get("Fan_Speed", {})
    if fan_speeds:
        label, value = next(iter(fan_speeds.items()))
        fan_speed_label.config(text=f"{label}: {value}")
    else:
        fan_speed_label.config(text="Fan Speed: N/A")

    root.after(1000, update_system_stats)  # Update every second

def get_sensors_data():
    sensor_data = {"Fan_Speed": {}}

    try:
        sensors_output = subprocess.check_output(
            ["sensors"], text=True, stderr=subprocess.DEVNULL
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sensor_data

    for line in sensors_output.splitlines():
        parts = line.split(":", maxsplit=1)
        if len(parts) != 2:
            continue

        label, value = parts
        if "fan" in label.lower() and "rpm" in value.lower():
            speed_value = value.split("RPM")[0].strip()
            sensor_data["Fan_Speed"][label.strip()] = speed_value

    return sensor_data

def run_benchmark():
    script_path = os.path.join(APP_DIR, "benchmark.sh")
    if not os.path.exists(script_path):
        messagebox.showerror("Benchmark", "benchmark.sh was not found in the application directory.")
        return

    run_terminal_task(f"bash {shlex.quote(script_path)}")


def set_fan_speed(speed_value: int, pwm_path: str):
    try:
        value = int(speed_value)
    except (TypeError, ValueError):
        messagebox.showerror("Fan Speed", "Invalid speed value provided.")
        return

    value = max(0, min(255, value))
    command = f"echo {value} | sudo tee {shlex.quote(pwm_path)}"
    run_terminal_task(command)


def fan_speed():
    pwm_paths = detect_pwm_paths()
    if not pwm_paths:
        messagebox.showwarning(
            "Fan Speed",
            "No writable PWM devices were detected. Ensure fan control is supported on this system.",
        )
        return

    fan_speed_window = tk.Toplevel(root)
    fan_speed_window.title("Fan Speed Control")
    fan_speed_window.geometry("420x240")
    fan_speed_window.config(bg="#2e3b4e")

    tk.Label(
        fan_speed_window,
        text="Adjust Fan Speed:",
        bg="#2e3b4e",
        fg="white",
        font=("Arial", 14),
    ).pack(pady=10)

    speed_slider = tk.Scale(
        fan_speed_window,
        from_=0,
        to=255,
        orient="horizontal",
        bg="#2e3b4e",
        fg="white",
        font=("Arial", 12),
    )
    speed_slider.set(128)
    speed_slider.pack(pady=10)

    tk.Label(
        fan_speed_window,
        text="PWM Device:",
        bg="#2e3b4e",
        fg="white",
        font=("Arial", 12),
    ).pack(pady=(10, 0))

    selected_pwm = tk.StringVar(value=pwm_paths[0])
    pwm_dropdown = ttk.Combobox(fan_speed_window, textvariable=selected_pwm, values=pwm_paths, state="readonly")
    pwm_dropdown.pack(pady=5, fill="x", padx=20)

    tk.Label(
        fan_speed_window,
        text="A terminal will open and prompt for sudo privileges when applying the new speed.",
        bg="#2e3b4e",
        fg="white",
        wraplength=360,
    ).pack(pady=5)

    def apply_speed():
        set_fan_speed(speed_slider.get(), selected_pwm.get())

    tk.Button(
        fan_speed_window,
        text="Set Fan Speed",
        command=apply_speed,
        bg="#1c2833",
        fg="white",
        font=("Arial", 12),
    ).pack(pady=10)


def launch_ddrescue_gui():
    window = tk.Toplevel(root)
    window.title("GNU ddrescue")
    window.geometry("420x320")

    tk.Label(window, text="Source device (e.g., /dev/sdb):").pack(pady=5)
    src_entry = tk.Entry(window, width=40)
    src_entry.pack()

    tk.Label(window, text="Destination image (e.g., /path/recovery.img):").pack(pady=5)
    dest_entry = tk.Entry(window, width=40)
    dest_entry.pack()

    tk.Label(window, text="Log file (e.g., /path/recovery.log):").pack(pady=5)
    log_entry = tk.Entry(window, width=40)
    log_entry.pack()

    def run_ddrescue_command():
        src = src_entry.get().strip()
        dest = dest_entry.get().strip()
        log = log_entry.get().strip()

        if not (src and dest and log):
            messagebox.showwarning("GNU ddrescue", "Please fill in source, destination, and log file paths.")
            return

        dest_path = Path(dest)
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.touch(exist_ok=True)
        except Exception as exc:
            messagebox.showerror("GNU ddrescue", f"Failed to prepare destination file: {exc}")
            return

        command = " ".join(
            [
                "sudo",
                "ddrescue",
                shlex.quote(src),
                shlex.quote(dest),
                shlex.quote(log),
            ]
        )

        run_terminal_task(command)
        window.destroy()

    tk.Button(
        window,
        text="Start",
        command=run_ddrescue_command,
        bg="#4CAF50",
        fg="white",
        font=("Arial", 12),
    ).pack(pady=20)

def run_speedtest():
    run_terminal_task("speedtest-cli")


def ping_test():
    run_terminal_task("ping -c 4 8.8.8.8")


def reboot():
    if messagebox.askyesno("Reboot", "Are you sure you want to reboot?"):
        os.system("systemctl reboot")


def shutdown():
    if messagebox.askyesno("Shutdown", "Are you sure you want to shut down?"):
        os.system("systemctl poweroff")


def restart_network():
    run_terminal_task("sudo systemctl restart NetworkManager")


def secure_wipe():
    """Securely wipe a selected drive using multiple overwrite passes."""

    def get_drives():
        try:
            output = subprocess.check_output(
                ["lsblk", "-d", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"],
                text=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            messagebox.showerror("Secure Wipe", f"Failed to list block devices: {exc}")
            return []

        drives_found = []
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue

            name, size, dev_type = parts[:3]
            if dev_type in {"rom", "loop", "part"}:
                continue

            mountpoint = parts[3] if len(parts) >= 4 else ""
            display = f"{name} ({size})"
            if mountpoint and mountpoint != "-":
                display += f" – mounted at {mountpoint}"

            drives_found.append({"path": f"/dev/{name}", "display": display})

        return drives_found

    def get_selected_drive():
        selection = drive_list.curselection()
        if not selection:
            return None
        return drives[selection[0]]

    def refresh_drives():
        nonlocal drives
        drives = get_drives()
        drive_list.delete(0, tk.END)
        for drive in drives:
            drive_list.insert(tk.END, drive["display"])
        selected_label.config(text="No drive selected")

    def create_wipe_script(device_path: str) -> str:
        temp_dir = tempfile.mkdtemp(prefix="wipe_")
        script_path = os.path.join(temp_dir, "wipe.sh")

        script_content = f"""#!/bin/bash
set -euo pipefail

TEMP_DIR={shlex.quote(temp_dir)}
trap 'rm -rf -- "$TEMP_DIR"' EXIT
device={shlex.quote(device_path)}

log_step() {{
    echo ""
    echo "==> $1"
}}

log_step "Pass 1: writing 0xFF pattern"
shred -v -n 0 --force --pattern=ff "$device"

log_step "Pass 2: writing zeros"
shred -v -n 0 --force --zero "$device"

log_step "Pass 3: writing random data"
shred -v -n 1 --force "$device"

log_step "Verification: read-only badblocks scan"
badblocks -sv "$device"

echo ""
echo "Secure wipe completed for $device"
"""

        with open(script_path, "w", encoding="utf-8") as script_file:
            script_file.write(script_content)

        os.chmod(script_path, 0o755)
        return script_path

    def on_wipe():
        selected_drive = get_selected_drive()
        if not selected_drive:
            messagebox.showwarning("Secure Wipe", "Please select a drive to wipe.")
            return

        confirm_message = (
            f"Are you sure you want to wipe {selected_drive['display']}?\n\n"
            "This process will:\n"
            "• Pass 1: write 0xFF pattern\n"
            "• Pass 2: write zeros\n"
            "• Pass 3: write random data\n"
            "• Verify with a read-only badblocks scan\n\n"
            "All data on the device will be permanently destroyed."
        )

        if not messagebox.askyesno("Confirm Secure Wipe", confirm_message):
            return

        script_path = create_wipe_script(selected_drive["path"])
        run_terminal_task(f"pkexec bash {shlex.quote(script_path)}")

    wipe_window = tk.Toplevel(root)
    wipe_window.title("Secure Wipe Tool")
    wipe_window.geometry("420x360")

    drives = get_drives()
    if not drives:
        messagebox.showwarning("Secure Wipe", "No eligible storage devices were found.")
        wipe_window.destroy()
        return

    frame = tk.Frame(wipe_window)
    frame.pack(fill="both", expand=True, padx=10, pady=10)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")

    drive_list = tk.Listbox(frame, selectmode="single", yscrollcommand=scrollbar.set)
    for drive in drives:
        drive_list.insert(tk.END, drive["display"])
    drive_list.pack(fill="both", expand=True)

    scrollbar.config(command=drive_list.yview)

    def on_select(_event):
        drive = get_selected_drive()
        if drive:
            selected_label.config(text=f"Selected: {drive['display']}")

    drive_list.bind("<<ListboxSelect>>", on_select)

    selected_label = tk.Label(wipe_window, text="No drive selected")
    selected_label.pack(pady=5)

    tk.Label(
        wipe_window,
        text="WARNING: This operation permanently erases the selected drive.",
        fg="red",
    ).pack(pady=10)

    tk.Button(wipe_window, text="Refresh Drive List", command=refresh_drives).pack(pady=5)
    tk.Button(wipe_window, text="Wipe Drive", command=on_wipe, bg="red", fg="white").pack(pady=10)

# --- GUI SETUP ---
root = tk.Tk()
root.title("Tech Toolbox")
root.geometry("700x850")
root.config(bg="#2e3b4e")

# --- SYSTEM MONITOR ---
fan_speed_label = tk.Label(root, text="Fan Speed: Loading...", bg="#2e3b4e", fg="white", font=("Arial", 14))
fan_speed_label.pack(pady=10)

cpu_label = tk.Label(root, text="CPU Usage:", bg="#2e3b4e", fg="white", font=("Arial", 12))
cpu_label.pack()
memory_label = tk.Label(root, text="Memory:", bg="#2e3b4e", fg="white", font=("Arial", 12))
memory_label.pack()
swap_label = tk.Label(root, text="Swap:", bg="#2e3b4e", fg="white", font=("Arial", 12))
swap_label.pack()
temp_label = tk.Label(root, text="CPU Temp:", bg="#2e3b4e", fg="white", font=("Arial", 12))
temp_label.pack()
disk_label = tk.Label(root, text="Disk Usage:", bg="#2e3b4e", fg="white", font=("Arial", 12))
disk_label.pack()
uptime_label = tk.Label(root, text="Uptime:", bg="#2e3b4e", fg="white", font=("Arial", 12))
uptime_label.pack()
internal_ip_label = tk.Label(root, text="Internal IP:", bg="#2e3b4e", fg="white", font=("Arial", 12))
internal_ip_label.pack()
external_ip_label = tk.Label(root, text="External IP:", bg="#2e3b4e", fg="white", font=("Arial", 12))
external_ip_label.pack()

# --- TOOL BUTTONS ---
tk.Label(root, text="Tools", font=("Arial", 14, "bold"), fg="white", bg="#2e3b4e").pack(pady=10)
button_frame = tk.Frame(root, bg="#2e3b4e")
button_frame.pack()

tool_commands = {
    "GParted": program_launcher("gparted"),
    "GNOME Disks": program_launcher("gnome-disks"),
    "GNU ddrescue": launch_ddrescue_gui,
    "Secure Wipe": secure_wipe,
    "PhotoRec": terminal_launcher("sudo photorec"),
    "Clonezilla": terminal_launcher("sudo clonezilla"),
    "ADB Devices": terminal_launcher("adb devices"),
    "Scrcpy (Screen Mirror)": program_launcher("scrcpy"),
    "Wireshark": program_launcher("wireshark"),
    "FileZilla": program_launcher("filezilla"),
    "BleachBit": program_launcher("bleachbit"),
    "Stacer": program_launcher("stacer"),
    "LibreOffice Writer": program_launcher("libreoffice --writer"),
    "CherryTree Notes": program_launcher("cherrytree"),
    "KeePassXC": program_launcher("keepassxc"),
    "Simple Scan": program_launcher("simple-scan"),
    "Nmap": terminal_launcher("nmap"),
    "SMART Monitoring": terminal_launcher("sudo smartctl -a /dev/sda"),
}

special_tools = {
    "Benchmark Script": run_benchmark,
    "Fan Speed": fan_speed,
    "Speedtest": run_speedtest,
    "Ping Test": ping_test,
    "Restart Network": restart_network,
    "Reboot": reboot,
    "Shutdown": shutdown
}

DEPENDENCY_MAP = {
    "GParted": ["gparted"],
    "GNOME Disks": ["gnome-disks"],
    "GNU ddrescue": ["ddrescue"],
    "Secure Wipe": ["lsblk", "shred", "badblocks", "pkexec"],
    "PhotoRec": ["photorec", "sudo"],
    "Clonezilla": ["clonezilla", "sudo"],
    "ADB Devices": ["adb"],
    "Scrcpy (Screen Mirror)": ["scrcpy"],
    "Wireshark": ["wireshark"],
    "FileZilla": ["filezilla"],
    "BleachBit": ["bleachbit"],
    "Stacer": ["stacer"],
    "LibreOffice Writer": ["libreoffice"],
    "CherryTree Notes": ["cherrytree"],
    "KeePassXC": ["keepassxc"],
    "Simple Scan": ["simple-scan"],
    "Nmap": ["nmap"],
    "SMART Monitoring": ["smartctl", "sudo"],
    "Benchmark Script": ["bash"],
    "Fan Speed": ["tee", "sudo"],
    "Speedtest": ["speedtest-cli"],
    "Ping Test": ["ping"],
    "Restart Network": ["systemctl", "sudo"],
    "Reboot": ["systemctl"],
    "Shutdown": ["systemctl"],
}

check_dependencies()

# --- Create buttons for all tools ---
row = 0
col = 0
for label, action in {**tool_commands, **special_tools}.items():
    btn = tk.Button(button_frame, text=label, command=action, bg="#1c2833", fg="white", font=("Arial", 10), width=30)
    btn.grid(row=row, column=col, padx=5, pady=3)
    row += 1
    if row >= 13:
        row = 0
        col += 1

tk.Button(root, text="Quit", command=root.quit, bg="#cc0000", fg="white", font=("Arial", 12)).pack(pady=10)

update_system_stats()
root.mainloop()


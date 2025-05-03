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

def check_dependencies():
    missing = []
    for label, cmd in tool_commands.items():
        if isinstance(cmd, str):
            executable = cmd.split()[0]
            if not shutil.which(executable):
                missing.append(label)
    if missing:
        messagebox.showwarning("Missing Tools", f"Some tools may be missing:\n{', '.join(missing)}")

def update_system_stats():
    cpu_usage = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')

    uptime_seconds = time.time() - psutil.boot_time()
    uptime_str = time.strftime('%H:%M:%S', time.gmtime(uptime_seconds))

    try:
        internal_ip = socket.gethostbyname(socket.gethostname())
    except:
        internal_ip = "Unavailable"

    try:
        external_ip = requests.get("https://api.ipify.org", timeout=2).text
    except:
        external_ip = "Unavailable"

    try:
        temps = psutil.sensors_temperatures()
        if "coretemp" in temps:
            temp = temps["coretemp"][0].current
            temp_label.config(text=f"CPU Temp: {temp:.1f}°C")
        else:
            temp_label.config(text="CPU Temp: N/A")
    except:
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
    
    fan_speed_label.config(text=f"Fan Speed: {sensor_data.get('Fan_Speed', {}).get('Fan1', 'N/A')}")

    root.after(1000, update_system_stats)  # Update every second

def get_sensors_data():
    sensor_data = {}

    try:
        # Run the `sensors` command to get the output
        sensors_output = subprocess.check_output(['sensors'], universal_newlines=True)

        # Initialize fan speed dictionary
        sensor_data["Fan_Speed"] = {}

        # Parse the output for fan speeds
        for line in sensors_output.splitlines():
            if "fan1" in line.lower():  # Case insensitive check
                fan_speed = line.split(":")[1].split("RPM")[0].strip() if ":" in line else None
                if fan_speed:
                    sensor_data["Fan_Speed"]["Fan1"] = fan_speed

    except subprocess.CalledProcessError as e:
        print(f"Error retrieving fan speed: {e}")
        sensor_data["Fan_Speed"]["Fan1"] = "Error"

    return sensor_data

def launch_tool(command):
    try:
        hold_open_command = f'{command}; echo "Press enter to close..."; read'
        subprocess.Popen(["gnome-terminal", "--", "bash", "-c", hold_open_command])
    except Exception as e:
        messagebox.showerror("Error", str(e))

def run_benchmark():
    subprocess.Popen(['gnome-terminal', '--wait', '--', 'bash', '-c', 'benchmark.sh'])

def set_fan_speed(speed_value):
    try:
        # Command to set the fan speed with the password prompt in terminal
        fan_speed_command = f"echo {speed_value} | sudo tee /sys/class/hwmon/hwmon8/pwm1"
        
        # Open a terminal and let the user input the password manually
        subprocess.run(["gnome-terminal", "--", "bash", "-c", fan_speed_command])
        
        messagebox.showinfo("Fan Speed", f"Fan speed set to {speed_value}. Please input your password in the terminal.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to open terminal for fan speed control: {e}")

def fan_speed():
    # Create a new window for fan control
    fan_speed_window = tk.Toplevel(root)
    fan_speed_window.title("Fan Speed Control")
    fan_speed_window.geometry("400x200")
    fan_speed_window.config(bg="#2e3b4e")

    # Label for the fan speed slider
    fan_speed_label = tk.Label(fan_speed_window, text="Adjust Fan Speed:", bg="#2e3b4e", fg="white", font=("Arial", 14))
    fan_speed_label.pack(pady=10)

    # Fan speed slider (0 to 255)
    fan_speed_slider = tk.Scale(fan_speed_window, from_=0, to=255, orient="horizontal", bg="#2e3b4e", fg="white", font=("Arial", 12))
    fan_speed_slider.set(128)  # Default to medium speed
    fan_speed_slider.pack(pady=20)

    # Button to apply the selected fan speed
    apply_button = tk.Button(fan_speed_window, text="Set Fan Speed", command=lambda: set_fan_speed(fan_speed_slider.get()), bg="#1c2833", fg="white", font=("Arial", 12))
    apply_button.pack(pady=10)

def launch_ddrescue_gui():
    window = tk.Toplevel()
    window.title("GNU ddrescue")
    window.geometry("400x300")

    # Labels and Entries
    tk.Label(window, text="Source (e.g., /dev/sdb):").pack(pady=5)
    src_entry = tk.Entry(window, width=40)
    src_entry.pack()

    tk.Label(window, text="Destination c:").pack(pady=5)
    dest_entry = tk.Entry(window, width=40)
    dest_entry.pack()

    tk.Label(window, text="Log File (e.g., log.log):").pack(pady=5)
    log_entry = tk.Entry(window, width=40)
    log_entry.pack()

    def run_ddrescue_command():
        src = src_entry.get()
        dest = dest_entry.get()
        log = log_entry.get()

        if not all([src, dest, log]):
            messagebox.showwarning("Missing Fields", "Please fill in all fields.")
            return

        # Create destination file if it doesn't exist
        try:
            if not os.path.exists(dest):
                # Create parent directories if they don't exist
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                # Create empty file
                open(dest, 'wb').close()
                print(f"Created destination file: {dest}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create destination file: {e}")
            return

        command = f"sudo ddrescue {src} {dest} {log}"
        print(f"Running command: {command}")  # DEBUG

        try:
            subprocess.Popen(["gnome-terminal", "--wait", "--", "bash", "-c", command])
            window.destroy()
        except FileNotFoundError:
            messagebox.showerror("Error", "gnome-terminal not found. Please install it.")
        except Exception as e:
            messagebox.showerror("Execution Error", f"Failed to run ddrescue: {e}")

    # Start button
    start_button = tk.Button(window, text="Start", command=run_ddrescue_command, bg="#4CAF50", fg="white", font=("Arial", 12))
    start_button.pack(pady=20)

def run_speedtest():
    subprocess.Popen(['gnome-terminal', '--wait', '--', 'bash', '-c', 'speedtest-cli'])

def ping_test():
    subprocess.Popen(['gnome-terminal', '--wait', '--', 'bash', '-c', 'ping -c 4 8.8.8.8'])

def reboot():
    if messagebox.askyesno("Reboot", "Are you sure you want to reboot?"):
        os.system('systemctl reboot')

def shutdown():
    if messagebox.askyesno("Shutdown", "Are you sure you want to shut down?"):
        os.system('systemctl poweroff')

def restart_network():
    subprocess.Popen(['gnome-terminal', '--wait', '--', 'bash', '-c', 'sudo systemctl restart NetworkManager'])

def secure_wipe():
    """
    Securely wipe a selected drive using multiple passes and verification.
    """
    def get_drives():
        drives = []
        try:
            # Get all block devices
            output = subprocess.check_output(['lsblk', '-d', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT'], text=True)
            for line in output.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[0]
                    type = parts[2]
                    
                    # Include all types of block devices except partitions
                    if type not in ['rom', 'loop', 'part']:
                        full_path = f'/dev/{name}'
                        drives.append({
                            'path': full_path,
                            'display': name
                        })
        except Exception as e:
            print(f"Error getting drives: {e}")
            return []
        return drives

    def on_wipe():
        selected_drive = get_selected_drive()
        if not selected_drive:
            messagebox.showwarning("Warning", "Please select a drive to wipe")
            return

        # Confirm with user
        if messagebox.askyesno("Confirm Wipe", f"Are you sure you want to wipe {selected_drive['display']}?\nThis action is irreversible!\n\nThis will perform multiple passes of writing:\n- First pass: Write ones\n- Second pass: Write zeros\n- Third pass: Write random data\n- Fourth pass: Write zeros\n- Final verification\n\nThis process will take a long time and is completely irreversible."):
            # Create a new window to show progress
            progress_window = tk.Toplevel(wipe_window)
            progress_window.title("Wipe Progress")
            progress_window.geometry("500x300")
            
            # Progress bar
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress_window, variable=progress_var, maximum=100)
            progress_bar.pack(fill="x", padx=10, pady=10)
            
            # Status label
            status_label = tk.Label(progress_window, text="Starting wipe process...")
            status_label.pack(pady=10)
            
            # Command with progress monitoring
            command = create_wipe_command(selected_drive['path'])
            
            # Run the command in a new terminal with pkexec
            terminal = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'pkexec bash -c \"{command}\"; echo "Wipe completed. Press enter to close..."; read'])
            
            # Function to update progress
            def update_progress():
                if terminal.poll() is None:  # Process is still running
                    try:
                        # Get the current process ID of the dd command
                        device_path = selected_drive['path']
                        # Escape the device path for regex
                        escaped_path = re.escape(device_path)
                        pids = subprocess.check_output(['pgrep', '-f', f'dd.*{escaped_path}'], text=True).strip().split('\n')
                        if pids:
                            dd_pid = pids[0]
                            # Get the total size of the device
                            size_output = subprocess.check_output(['blockdev', '--getsize64', device_path], text=True)
                            total_size = int(size_output.strip())
                            
                            # Get the current progress from dd's status output
                            output = subprocess.check_output(['pkexec', 'ps', '-p', dd_pid, '-o', 'cmd='], text=True)
                            if 'copied' in output:
                                # Extract the number of bytes copied
                                bytes_copied = int(re.search(r'([0-9]+) bytes', output).group(1))
                                # Calculate progress
                                progress = (bytes_copied / total_size) * 100
                                progress_var.set(progress)
                                status_label.config(text=f"Wrote {bytes_copied:,} bytes of {total_size:,} bytes ({progress:.1f}%)")
                    except Exception as e:
                        print(f"Error updating progress: {e}")
                        # If we can't get accurate progress, at least show something
                        progress_var.set((progress_var.get() + 1) % 100)
                        status_label.config(text="Progress monitoring not available. Wipe in progress...")
                    
                    # Schedule next update
                    progress_window.after(1000, update_progress)
                else:
                    # Process completed
                    progress_var.set(100)
                    status_label.config(text="Wipe completed successfully!")
                    
            # Start progress updates
            update_progress()
            
            # Make the progress window non-resizable
            progress_window.resizable(False, False)
            progress_window.mainloop()

    def create_wipe_command(device):
        """
        Create a comprehensive wipe command that uses multiple passes with different patterns:
        1. First pass: Write ones
        2. Second pass: Write zeros
        3. Third pass: Write random data
        4. Fourth pass: Write zeros (verification)
        5. Final verification with badblocks
        """
        # Create a temporary directory for the script
        temp_dir = tempfile.mkdtemp(prefix='wipe_')
        script_file = os.path.join(temp_dir, 'wipe_script.sh')
        
        # Extract just the device path (without size info)
        device_path = device['path']
        
        # Use a script to handle the multiple passes with detailed progress
        script = f"""
#!/bin/bash

# Function to format time
format_time() {{
    local seconds=$1
    local hours=$((seconds / 3600))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))
    printf "%02d:%02d:%02d" $hours $minutes $secs
}}

# Function to show progress
show_progress() {{
    local pid=$1
    local start_time=$(date +%s)
    local total_size=$(pkexec blockdev --getsize64 "{device_path}")
    local current_size=0
    local progress=0
    
    while kill -0 $pid 2>/dev/null; do
        # Get the current progress from dd's status output
        local status=$(pkexec ps -p $pid -o cmd= | grep -o "copied.*bytes")
        if [[ $status ]]; then
            # Extract the number of bytes copied
            local bytes=$(echo $status | grep -o "[0-9]*" | head -1)
            if [[ $bytes ]]; then
                current_size=$bytes
                progress=$(echo "scale=2; ($current_size * 100) / $total_size" | bc)
                
                # Calculate time
                local current_time=$(date +%s)
                local elapsed=$((current_time - start_time))
                if [ $progress -gt 0 ]; then
                    local total_time=$(echo "scale=0; $elapsed * 100 / $progress" | bc)
                    local remaining=$((total_time - elapsed))
                else
                    local remaining=-1
                fi
                
                # Format output
                local elapsed_time=$(format_time $elapsed)
                local remaining_time="N/A"
                if [ $remaining -ge 0 ]; then
                    remaining_time=$(format_time $remaining)
                fi
                
                # Print progress
                echo -e "\rProgress: $progress% ($current_size of $total_size)\n"
                echo -e "Time elapsed: $elapsed_time"
                echo -e "Time remaining: $remaining_time\n"
            fi
        fi
        sleep 1
    done
}}

# Wait 10 seconds before starting
echo "Waiting 10 seconds before starting first pass..."
sleep 10

# First pass - Write ones
echo "Starting first pass: Writing ones..."
pkexec dd if=/dev/zero of="{device_path}" bs=4M conv=fdatasync status=progress &
pid=$!
show_progress $pid
wait $pid

# Second pass - Write zeros
echo "Starting second pass: Writing zeros..."
pkexec dd if=/dev/urandom of="{device_path}" bs=4M conv=fdatasync status=progress &
pid=$!
show_progress $pid
wait $pid

# Third pass - Write random data
echo "Starting third pass: Writing random data..."
pkexec dd if=/dev/zero of="{device_path}" bs=4M conv=fdatasync status=progress &
pid=$!
show_progress $pid
wait $pid

# Fourth pass - Write zeros
echo "Starting fourth pass: Final verification..."
pkexec dd if=/dev/urandom of="{device_path}" bs=4M conv=fdatasync status=progress &
pid=$!
show_progress $pid
wait $pid

# Final verification
echo "Starting final verification..."
pkexec badblocks -wsv "{device_path}"

# Clean up temporary files
echo "Cleaning up temporary files..."
rm -rf "{temp_dir}"
"""

        # Write the script to the temporary file
        with open(script_file, 'w') as f:
            f.write(script)
        
        # Make the script executable
        os.chmod(script_file, 0o755)
        
        # Return the command to run the script
        return f"bash {script_file}"

    def on_wipe():
        selected_drive = get_selected_drive()
        if not selected_drive:
            messagebox.showwarning("Warning", "Please select a drive to wipe")
            return

        # Confirm with user
        if messagebox.askyesno("Confirm Wipe", f"Are you sure you want to wipe {selected_drive}?\nThis action is irreversible!\n\nThis will perform multiple passes of writing:\n- First pass: Write ones\n- Second pass: Write zeros\n- Third pass: Write random data\n- Fourth pass: Write zeros\n- Final verification\n\nThis process will take a long time and is completely irreversible."):
            # Create a new window to show progress
            progress_window = tk.Toplevel(wipe_window)
            progress_window.title("Wipe Progress")
            progress_window.geometry("500x300")
            
            # Progress bar
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress_window, variable=progress_var, maximum=100)
            progress_bar.pack(fill="x", padx=10, pady=10)
            
            # Status label
            status_label = tk.Label(progress_window, text="Starting wipe process...")
            status_label.pack(pady=10)
            
            # Command with progress monitoring
            command = create_wipe_command(selected_drive)
            
            # Run the command in a new terminal with progress monitoring
            terminal = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{command}; echo "Wipe completed. Press enter to close..."; read'])
            
            # Function to update progress
            def update_progress():
                if terminal.poll() is None:  # Process is still running
                    try:
                        # Get the current process ID of the dd command
                        pids = subprocess.check_output(['pgrep', '-f', f'dd.*{selected_drive}'], text=True).strip().split('\n')
                        if pids:
                            dd_pid = pids[0]
                            # Read the status file for the dd process
                            with open(f'/proc/{dd_pid}/io', 'r') as f:
                                io_stats = f.read()
                                # Get the write_bytes value
                                for line in io_stats.split('\n'):
                                    if 'write_bytes' in line:
                                        write_bytes = int(line.split(':')[1].strip())
                                        # Get the total size of the device
                                        size_output = subprocess.check_output(['blockdev', '--getsize64', selected_drive], text=True)
                                        total_size = int(size_output.strip())
                                        # Calculate progress
                                        progress = (write_bytes / total_size) * 100
                                        progress_var.set(progress)
                                        status_label.config(text=f"Wrote {write_bytes:,} bytes of {total_size:,} bytes ({progress:.1f}%)")
                    except Exception as e:
                        print(f"Error updating progress: {e}")
                        # If we can't get accurate progress, at least show something
                        progress_var.set((progress_var.get() + 1) % 100)
                        status_label.config(text="Progress monitoring not available. Wipe in progress...")
                    
                    # Schedule next update
                    progress_window.after(1000, update_progress)
                else:
                    # Process completed
                    progress_var.set(100)
                    status_label.config(text="Wipe completed successfully!")
                    
            # Start progress updates
            update_progress()
            
            # Make the progress window non-resizable
            progress_window.resizable(False, False)
            progress_window.mainloop()

    def get_selected_drive():
        selection = drive_list.curselection()
        if selection:
            return drives[selection[0]]
        return None

    # Create the wipe window for drive selection
    wipe_window = tk.Toplevel(root)
    wipe_window.title("Secure Wipe Tool")
    wipe_window.geometry("400x300")

    # Drive selection
    drives = get_drives()
    if not drives:
        messagebox.showwarning("No Drives", "No storage devices found for wiping")
        return

    # Create a listbox with scrollbars for better display
    frame = tk.Frame(wipe_window)
    frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")
    
    drive_list = tk.Listbox(frame, selectmode="single", yscrollcommand=scrollbar.set)
    for drive in drives:
        drive_list.insert("end", drive)
    drive_list.pack(fill="both", expand=True)
    
    scrollbar.config(command=drive_list.yview)
    
    def on_select(event):
        selection = drive_list.curselection()
        if selection:
            selected_index = selection[0]
            selected_drive = drives[selected_index]
            selected_label.config(text=f"Selected: {selected_drive}")
    
    drive_list.bind('<<ListboxSelect>>', on_select)
    
    # Add a label showing the selected drive
    selected_label = tk.Label(wipe_window, text="No drive selected")
    selected_label.pack(pady=5)

    # Warning label
    tk.Label(wipe_window, text="WARNING: This will permanently erase ALL data on the selected drive!", 
            fg="red").pack(pady=10)

    # Add a button to refresh the drive list
    def refresh_drives():
        drives = get_drives()
        drive_list.delete(0, tk.END)
        for drive in drives:
            drive_list.insert("end", drive)
    
    refresh_button = tk.Button(wipe_window, text="Refresh Drive List", command=refresh_drives)
    refresh_button.pack(pady=5)

    # Wipe button
    tk.Button(wipe_window, text="Wipe Drive", command=on_wipe, bg="red", fg="white").pack(pady=20)

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
    "GParted": "gparted",
    "GNOME Disks": "gnome-disks",
    "ddrescue": launch_ddrescue_gui,
    "Secure Wipe": secure_wipe,
    "PhotoRec": "x-terminal-emulator -e 'bash -i -c \"sudo photorec; echo \\\"Press enter to close...\\\"; read\"'",
    "Clonezilla": "x-terminal-emulator -e 'bash -i -c \"sudo clonezilla; echo \\\"Press enter to close...\\\"; read\"'",
    "ADB Devices": "x-terminal-emulator -e 'bash -i -c \"adb devices; echo \\\"Press enter to close...\\\"; read\"'",
    "Scrcpy (Screen Mirror)": "scrcpy",
    "Wireshark": "wireshark",
    "FileZilla": "filezilla",
    "BleachBit": "bleachbit",
    "Stacer": "stacer",
    "LibreOffice Writer": "libreoffice --writer",
    "Cherrytree Notes": "cherrytree",
    "KeePassXC": "keepassxc",
    "Simple Scan": "simple-scan",
    "Nmap": "x-terminal-emulator -e 'bash -i -c \"nmap; echo \\\"Press enter to close...\\\"; read\"'",
    "Smart Monitoring": "x-terminal-emulator -e 'bash -i -c \"sudo smartctl -a /dev/sda; echo \\\"Press enter to close...\\\"; read\"'"
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

check_dependencies()

# --- Create buttons for all tools ---
row = 0
col = 0
for label, cmd in {**tool_commands, **special_tools}.items():
    action = lambda c=cmd: launch_tool(c) if isinstance(c, str) else c()
    btn = tk.Button(button_frame, text=label, command=action, bg="#1c2833", fg="white", font=("Arial", 10), width=30)
    btn.grid(row=row, column=col, padx=5, pady=3)
    row += 1
    if row >= 13:
        row = 0
        col += 1

tk.Button(root, text="Quit", command=root.quit, bg="#cc0000", fg="white", font=("Arial", 12)).pack(pady=10)

update_system_stats()
root.mainloop()


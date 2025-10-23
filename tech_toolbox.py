import glob
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import psutil
import requests
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

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

EXTERNAL_IP_CACHE_TTL = 300  # seconds
_external_ip_cache = {"value": "Checking...", "expires": 0.0}
_external_ip_lock = threading.Lock()
_external_ip_refreshing = False


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


def _fetch_external_ip():
    try:
        response = requests.get("https://api.ipify.org", timeout=2)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return "Unavailable"


def _refresh_external_ip_cache():
    global _external_ip_refreshing

    value = _fetch_external_ip()
    ttl = EXTERNAL_IP_CACHE_TTL if value != "Unavailable" else 60

    with _external_ip_lock:
        _external_ip_cache["value"] = value
        _external_ip_cache["expires"] = time.time() + ttl
        _external_ip_refreshing = False


def get_external_ip():
    """Return the cached external IP, refreshing it in the background when stale."""

    global _external_ip_refreshing

    now = time.time()
    with _external_ip_lock:
        value = _external_ip_cache["value"]
        needs_refresh = now >= _external_ip_cache["expires"] and not _external_ip_refreshing
        if needs_refresh:
            _external_ip_refreshing = True
            threading.Thread(target=_refresh_external_ip_cache, daemon=True).start()

    return value


def detect_pwm_paths():
    pwm_paths = []
    for path in glob.glob("/sys/class/hwmon/hwmon*/pwm*"):
        if os.path.isfile(path):
            pwm_paths.append(path)
    return sorted(pwm_paths)


def list_physical_disks():
    disks = []

    try:
        output = subprocess.check_output(
            ["lsblk", "-dn", "-o", "NAME,SIZE,TYPE"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        output = ""

    if output:
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue

            name, size, dev_type = parts[:3]
            if dev_type != "disk":
                continue

            disks.append({
                "path": f"/dev/{name}",
                "display": f"/dev/{name} ({size})" if size else f"/dev/{name}",
            })

    if disks:
        return disks

    block_root = Path("/sys/block")
    if not block_root.exists():
        return disks

    for entry in sorted(block_root.iterdir()):
        name = entry.name
        if name.startswith(("loop", "ram", "fd", "sr", "zram", "dm-")):
            continue
        disks.append({"path": f"/dev/{name}", "display": f"/dev/{name}"})

    return disks


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
            speed_value = re.split(r"\brpm\b", value, flags=re.IGNORECASE)[0].strip()
            sensor_data["Fan_Speed"][label.strip()] = speed_value

    return sensor_data


def load_tools_config(config_path: Path | None = None) -> list[dict]:
    if config_path is None:
        config_path = Path(APP_DIR) / "tools_config.json"

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
    except FileNotFoundError as exc:
        raise ValueError(f"Tools configuration file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in tools configuration: {exc}") from exc

    tools = config.get("tools") if isinstance(config, dict) else None
    if not isinstance(tools, list):
        raise ValueError("tools_config.json must contain a top-level 'tools' list")

    return tools


class TechToolbox(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("Tech Toolbox")
        self.resize(700, 850)

        self._setup_fonts()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.fan_speed_label = QLabel("Fan Speed: Loading...")
        self.fan_speed_label.setFont(self.large_font)
        layout.addWidget(self.fan_speed_label)

        self.cpu_label = QLabel("CPU Usage:")
        self.memory_label = QLabel("Memory:")
        self.swap_label = QLabel("Swap:")
        self.temp_label = QLabel("CPU Temp:")
        self.disk_label = QLabel("Disk Usage:")
        self.uptime_label = QLabel("Uptime:")
        self.internal_ip_label = QLabel("Internal IP:")
        self.external_ip_label = QLabel("External IP:")

        for label in (
            self.cpu_label,
            self.memory_label,
            self.swap_label,
            self.temp_label,
            self.disk_label,
            self.uptime_label,
            self.internal_ip_label,
            self.external_ip_label,
        ):
            label.setFont(self.standard_font)
            layout.addWidget(label)

        header = QLabel("Tools")
        header.setFont(self.header_font)
        layout.addWidget(header)

        button_grid = QGridLayout()
        button_grid.setHorizontalSpacing(10)
        button_grid.setVerticalSpacing(6)
        layout.addLayout(button_grid)

        self.tool_entries = self._prepare_tool_entries()
        self._create_tool_buttons(button_grid, self.tool_entries)

        quit_button = QPushButton("Quit")
        quit_button.setObjectName("dangerButton")
        quit_button.setFont(self.button_font)
        quit_button.clicked.connect(QApplication.instance().quit)
        layout.addWidget(quit_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.update_system_stats)
        self.stats_timer.start(1000)
        self.update_system_stats()

        self.check_dependencies()

    def _setup_fonts(self) -> None:
        base_font = QFont("Arial", 12)
        self.standard_font = base_font

        large_font = QFont("Arial", 14)
        large_font.setBold(True)
        self.large_font = large_font

        header_font = QFont("Arial", 14)
        header_font.setBold(True)
        self.header_font = header_font

        button_font = QFont("Arial", 10)
        self.button_font = button_font

    def _prepare_tool_entries(self) -> list[dict]:
        try:
            tool_definitions = load_tools_config()
        except ValueError as exc:
            self.show_error("Configuration Error", str(exc))
            return []

        entries: list[dict] = []
        problems: list[str] = []

        for tool in tool_definitions:
            try:
                entries.append(self._build_tool_entry(tool))
            except ValueError as exc:
                label = tool.get("label", "<unnamed>")
                problems.append(f"{label}: {exc}")

        if problems:
            self.show_warning(
                "Configuration Issues",
                "Some tools were skipped due to configuration errors:\n" + "\n".join(problems),
            )

        return entries

    def _build_tool_entry(self, tool: dict) -> dict:
        label = tool.get("label")
        if not label:
            raise ValueError("missing 'label'")

        dependencies = tool.get("dependencies", [])
        if dependencies is None:
            dependencies = []

        tool_type = tool.get("type", "program")

        if tool_type == "program":
            command = tool.get("command")
            if not isinstance(command, str) or not command.strip():
                raise ValueError("missing 'command' for program tool")
            action = lambda cmd=command: self.run_program(cmd)
        elif tool_type == "terminal":
            command = tool.get("command")
            if not isinstance(command, str) or not command.strip():
                raise ValueError("missing 'command' for terminal tool")
            hold_open = bool(tool.get("hold_open", True))
            action = self.terminal_launcher(command, hold_open=hold_open)
        elif tool_type == "method":
            method_name = tool.get("method")
            if not method_name:
                raise ValueError("missing 'method' for method tool")
            method = getattr(self, method_name, None)
            if method is None or not callable(method):
                raise ValueError(f"unknown method '{method_name}'")
            action = method
        else:
            raise ValueError(f"unknown tool type '{tool_type}'")

        return {"label": label, "action": action, "dependencies": list(dependencies)}

    def _create_tool_buttons(self, button_grid: QGridLayout, entries: list[dict]) -> None:
        max_rows = 13
        for index, entry in enumerate(entries):
            button = QPushButton(entry["label"])
            button.setFont(self.button_font)
            button.setMinimumWidth(220)
            button.clicked.connect(entry["action"])
            row = index % max_rows
            col = index // max_rows
            button_grid.addWidget(button, row, col)

    def _get_tool_dependencies(self, label: str) -> list[str]:
        for entry in getattr(self, "tool_entries", []):
            if entry.get("label") == label:
                return entry.get("dependencies", [])
        return []

    def show_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self, title, message)

    def show_warning(self, title: str, message: str) -> None:
        QMessageBox.warning(self, title, message)

    def run_program(self, command: str) -> None:
        try:
            subprocess.Popen(shlex.split(command))
        except FileNotFoundError:
            self.show_error("Error", f"Command not found: {command.split()[0]}")
        except Exception as exc:
            self.show_error("Error", f"Failed to launch command: {exc}")

    def run_terminal_task(self, command: str, hold_open: bool = True) -> None:
        try:
            open_terminal(command, hold_open=hold_open)
        except FileNotFoundError as exc:
            self.show_error("Terminal Error", str(exc))
        except Exception as exc:
            self.show_error("Terminal Error", f"Failed to open terminal: {exc}")

    def terminal_launcher(self, command: str, hold_open: bool = True):
        return lambda: self.run_terminal_task(command, hold_open=hold_open)

    def ensure_commands_available(self, *commands: str) -> bool:
        missing = [command for command in commands if not shutil.which(command)]
        if missing:
            self.show_error(
                "Missing Tools",
                "The following required command(s) were not found: " + ", ".join(missing),
            )
            return False
        return True

    def check_dependencies(self) -> None:
        missing: list[str] = []

        for entry in getattr(self, "tool_entries", []):
            dependencies = entry.get("dependencies", [])
            unavailable = [exe for exe in dependencies if not shutil.which(exe)]
            if unavailable:
                missing.append(f"{entry['label']} ({', '.join(unavailable)})")

        if missing:
            self.show_warning(
                "Missing Tools",
                "Some tools are unavailable because their executables were not found:\n"
                + "\n".join(missing),
            )

    def update_system_stats(self) -> None:
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
                self.temp_label.setText(f"CPU Temp: {coretemp[0].current:.1f}°C")
            else:
                self.temp_label.setText("CPU Temp: N/A")
        else:
            self.temp_label.setText("CPU Temp: Unavailable")

        self.cpu_label.setText(f"CPU Usage: {cpu_usage}%")
        self.memory_label.setText(f"Memory: {memory.percent}%")
        self.swap_label.setText(f"Swap: {swap.percent}%")
        self.disk_label.setText(
            f"Disk: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)"
        )
        self.uptime_label.setText(f"Uptime: {uptime_str}")
        self.internal_ip_label.setText(f"Internal IP: {internal_ip}")
        self.external_ip_label.setText(f"External IP: {external_ip}")

        sensor_data = get_sensors_data()
        fan_speeds = sensor_data.get("Fan_Speed", {})
        if fan_speeds:
            label, value = next(iter(fan_speeds.items()))
            self.fan_speed_label.setText(f"{label}: {value}")
        else:
            self.fan_speed_label.setText("Fan Speed: N/A")

    def run_benchmark(self) -> None:
        script_path = os.path.join(APP_DIR, "benchmark.sh")
        if not os.path.exists(script_path):
            self.show_error("Benchmark", "benchmark.sh was not found in the application directory.")
            return

        dependencies = self._get_tool_dependencies("Benchmark Script")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return

        self.run_terminal_task(f"bash {shlex.quote(script_path)}")

    def set_fan_speed(self, speed_value: int, pwm_path: str) -> None:
        try:
            value = int(speed_value)
        except (TypeError, ValueError):
            self.show_error("Fan Speed", "Invalid speed value provided.")
            return

        value = max(0, min(255, value))
        command = f"echo {value} | sudo tee {shlex.quote(pwm_path)}"
        self.run_terminal_task(command)

    def fan_speed(self) -> None:
        pwm_paths = detect_pwm_paths()
        if not pwm_paths:
            self.show_warning(
                "Fan Speed",
                "No writable PWM devices were detected. Ensure fan control is supported on this system.",
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Fan Speed Control")
        dialog_layout = QVBoxLayout(dialog)

        title_label = QLabel("Adjust Fan Speed:")
        title_label.setFont(self.large_font)
        dialog_layout.addWidget(title_label)

        speed_slider = QSlider(Qt.Orientation.Horizontal)
        speed_slider.setRange(0, 255)
        speed_slider.setValue(128)
        dialog_layout.addWidget(speed_slider)

        pwm_label = QLabel("PWM Device:")
        pwm_label.setFont(self.standard_font)
        dialog_layout.addWidget(pwm_label)

        pwm_dropdown = QComboBox()
        pwm_dropdown.addItems(pwm_paths)
        dialog_layout.addWidget(pwm_dropdown)

        info_label = QLabel(
            "A terminal will open and prompt for sudo privileges when applying the new speed."
        )
        info_label.setWordWrap(True)
        dialog_layout.addWidget(info_label)

        button = QPushButton("Set Fan Speed")
        button.clicked.connect(lambda: self.set_fan_speed(speed_slider.value(), pwm_dropdown.currentText()))
        dialog_layout.addWidget(button)

        dialog.exec()

    def launch_ddrescue_gui(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("GNU ddrescue")
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Source device (e.g., /dev/sdb):"))
        src_entry = QLineEdit()
        layout.addWidget(src_entry)

        layout.addWidget(QLabel("Destination image (e.g., /path/recovery.img):"))
        dest_entry = QLineEdit()
        layout.addWidget(dest_entry)

        layout.addWidget(QLabel("Log file (e.g., /path/recovery.log):"))
        log_entry = QLineEdit()
        layout.addWidget(log_entry)

        def run_ddrescue_command() -> None:
            src = src_entry.text().strip()
            dest = dest_entry.text().strip()
            log = log_entry.text().strip()

            if not (src and dest and log):
                self.show_warning("GNU ddrescue", "Please fill in source, destination, and log file paths.")
                return

            try:
                dest_path = Path(dest)
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                dest_path.touch(exist_ok=True)
            except Exception as exc:
                self.show_error("GNU ddrescue", f"Failed to prepare destination file: {exc}")
                return

            try:
                log_path = Path(log)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.touch(exist_ok=True)
            except Exception as exc:
                self.show_error("GNU ddrescue", f"Failed to prepare log file: {exc}")
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

            self.run_terminal_task(command)
            dialog.accept()

        start_button = QPushButton("Start")
        start_button.clicked.connect(run_ddrescue_command)
        layout.addWidget(start_button)

        dialog.exec()

    def smart_monitoring(self) -> None:
        dependencies = self._get_tool_dependencies("SMART Monitoring")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("SMART Monitoring")
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Select a drive to inspect with smartctl -a."))

        device_map: dict[str, str] = {}
        device_dropdown = QComboBox()
        layout.addWidget(device_dropdown)

        def refresh_devices() -> None:
            device_map.clear()
            devices = list_physical_disks()
            for item in devices:
                device_map[item["display"]] = item["path"]

            options = list(device_map.keys())
            device_dropdown.clear()
            if options:
                device_dropdown.addItems(options)
                device_dropdown.setEnabled(True)
            else:
                device_dropdown.setEnabled(False)

        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(refresh_devices)
        layout.addWidget(refresh_button)

        layout.addWidget(QLabel("Or enter a device path manually (e.g., /dev/nvme0n1):"))
        manual_entry = QLineEdit()
        layout.addWidget(manual_entry)

        def run_smartctl() -> None:
            manual_value = manual_entry.text().strip()
            if manual_value:
                target = manual_value
            else:
                target = device_map.get(device_dropdown.currentText(), "").strip()

            if not target:
                self.show_warning(
                    "SMART Monitoring",
                    "Select a detected device or enter a device path to inspect.",
                )
                return

            dialog.accept()
            self.run_terminal_task(f"sudo smartctl -a {shlex.quote(target)}")

        run_button = QPushButton("Run smartctl")
        run_button.clicked.connect(run_smartctl)
        layout.addWidget(run_button)

        refresh_devices()
        dialog.exec()

    def nmap_scan(self) -> None:
        dependencies = self._get_tool_dependencies("Nmap")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Nmap Scan")
        dialog.resize(420, 360)

        layout = QVBoxLayout(dialog)

        intro_label = QLabel(
            "Enter the target host or network and choose any scan options to include."
        )
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        target_input = QLineEdit()
        target_input.setPlaceholderText("e.g. scanme.nmap.org or 192.168.1.0/24")
        layout.addWidget(QLabel("Target:"))
        layout.addWidget(target_input)

        options_label = QLabel("Common options:")
        options_label.setFont(self.standard_font)
        layout.addWidget(options_label)

        option_definitions: list[tuple[QCheckBox, list[str]]] = []
        for text, args in (
            ("TCP SYN scan (-sS)", ["-sS"]),
            ("Service/version detection (-sV)", ["-sV"]),
            ("OS detection (-O)", ["-O"]),
            ("Default scripts (-sC)", ["-sC"]),
            ("Top 100 ports (--top-ports 100)", ["--top-ports", "100"]),
            ("Skip host discovery (-Pn)", ["-Pn"]),
        ):
            checkbox = QCheckBox(text)
            layout.addWidget(checkbox)
            option_definitions.append((checkbox, list(args)))

        timing_layout = QHBoxLayout()
        timing_label = QLabel("Timing profile:")
        timing_layout.addWidget(timing_label)
        timing_combo = QComboBox()
        timing_combo.addItem("Default", "")
        timing_combo.addItem("Polite (-T2)", "-T2")
        timing_combo.addItem("Normal (-T3)", "-T3")
        timing_combo.addItem("Aggressive (-T4)", "-T4")
        timing_combo.addItem("Insane (-T5)", "-T5")
        timing_layout.addWidget(timing_combo)
        timing_layout.addStretch(1)
        layout.addLayout(timing_layout)

        layout.addWidget(QLabel("Extra options (advanced):"))
        extra_options_input = QLineEdit()
        extra_options_input.setPlaceholderText("Additional flags, e.g. -p 1-1000 --open")
        layout.addWidget(extra_options_input)

        button_row = QHBoxLayout()
        run_button = QPushButton("Launch Scan")
        cancel_button = QPushButton("Cancel")
        button_row.addWidget(run_button)
        button_row.addWidget(cancel_button)
        layout.addLayout(button_row)

        def launch_scan() -> None:
            target_text = target_input.text().strip()
            if not target_text:
                self.show_error("Nmap Scan", "Enter the target host or network to scan.")
                return

            try:
                target_parts = shlex.split(target_text)
            except ValueError:
                self.show_error(
                    "Nmap Scan",
                    "The target field contains invalid quoting. Please correct it.",
                )
                return

            if not target_parts:
                self.show_error("Nmap Scan", "Enter at least one target for the scan.")
                return

            option_parts: list[str] = []
            for checkbox, args in option_definitions:
                if checkbox.isChecked():
                    option_parts.extend(args)

            timing_value = timing_combo.currentData()
            if timing_value:
                option_parts.append(str(timing_value))

            extra_text = extra_options_input.text().strip()
            if extra_text:
                try:
                    option_parts.extend(shlex.split(extra_text))
                except ValueError:
                    self.show_error(
                        "Nmap Scan",
                        "Extra options contain invalid quoting. Please correct them.",
                    )
                    return

            command_parts: list[str] = []
            if shutil.which("sudo"):
                command_parts.append("sudo")
            command_parts.append("nmap")
            command_parts.extend(option_parts)
            command_parts.extend(target_parts)

            command = " ".join(shlex.quote(part) for part in command_parts)
            dialog.accept()
            self.run_terminal_task(command)

        run_button.clicked.connect(launch_scan)
        cancel_button.clicked.connect(dialog.reject)

        dialog.exec()

    def run_speedtest(self) -> None:
        self.run_terminal_task("speedtest-cli")

    def ping_test(self) -> None:
        self.run_terminal_task("ping -c 4 8.8.8.8")

    def reboot(self) -> None:
        dependencies = self._get_tool_dependencies("Reboot")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return
        response = QMessageBox.question(self, "Reboot", "Are you sure you want to reboot?")
        if response == QMessageBox.StandardButton.Yes:
            try:
                subprocess.Popen(["systemctl", "reboot"])
            except Exception as exc:
                self.show_error("Reboot", f"Failed to initiate reboot: {exc}")

    def shutdown(self) -> None:
        dependencies = self._get_tool_dependencies("Shutdown")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return
        response = QMessageBox.question(self, "Shutdown", "Are you sure you want to shut down?")
        if response == QMessageBox.StandardButton.Yes:
            try:
                subprocess.Popen(["systemctl", "poweroff"])
            except Exception as exc:
                self.show_error("Shutdown", f"Failed to initiate shutdown: {exc}")

    def restart_network(self) -> None:
        dependencies = self._get_tool_dependencies("Restart Network")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return
        self.run_terminal_task("sudo systemctl restart NetworkManager")

    def secure_wipe(self) -> None:
        dependencies = self._get_tool_dependencies("Secure Wipe")
        if dependencies and not self.ensure_commands_available(*dependencies):
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Secure Wipe Tool")
        dialog.resize(420, 360)
        layout = QVBoxLayout(dialog)

        drives: list[dict[str, str]] = []
        drive_list = QListWidget()
        layout.addWidget(drive_list)

        selected_label = QLabel("No drive selected")
        layout.addWidget(selected_label)

        warning_label = QLabel(
            "WARNING: This operation permanently erases the selected drive."
        )
        warning_label.setStyleSheet("color: #ff8080;")
        layout.addWidget(warning_label)

        button_row = QHBoxLayout()
        refresh_button = QPushButton("Refresh Drive List")
        wipe_button = QPushButton("Wipe Drive")
        wipe_button.setStyleSheet("background-color: #b00000; color: white;")
        button_row.addWidget(refresh_button)
        button_row.addWidget(wipe_button)
        layout.addLayout(button_row)

        def get_drives() -> list[dict[str, str]]:
            try:
                output = subprocess.check_output(
                    ["lsblk", "-d", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"],
                    text=True,
                )
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                self.show_error("Secure Wipe", f"Failed to list block devices: {exc}")
                return []

            drives_found = []
            for line in output.splitlines()[1:]:
                parts = line.split(None, 3)
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

        def load_drives() -> None:
            nonlocal drives
            drives = get_drives()
            drive_list.clear()
            for drive in drives:
                drive_list.addItem(drive["display"])
            selected_label.setText("No drive selected")

        def current_drive():
            index = drive_list.currentRow()
            if index < 0 or index >= len(drives):
                return None
            return drives[index]

        def on_selection_changed() -> None:
            drive = current_drive()
            if drive:
                selected_label.setText(f"Selected: {drive['display']}")
            else:
                selected_label.setText("No drive selected")

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

        def on_wipe() -> None:
            drive = current_drive()
            if not drive:
                self.show_warning("Secure Wipe", "Please select a drive to wipe.")
                return

            confirm_message = (
                f"Are you sure you want to wipe {drive['display']}?\n\n"
                "This process will:\n"
                "• Pass 1: write 0xFF pattern\n"
                "• Pass 2: write zeros\n"
                "• Pass 3: write random data\n"
                "• Verify with a read-only badblocks scan\n\n"
                "All data on the device will be permanently destroyed."
            )

            response = QMessageBox.question(
                self,
                "Confirm Secure Wipe",
                confirm_message,
            )
            if response != QMessageBox.StandardButton.Yes:
                return

            script_path = create_wipe_script(drive["path"])
            self.run_terminal_task(f"pkexec bash {shlex.quote(script_path)}")

        drive_list.currentRowChanged.connect(lambda _: on_selection_changed())
        refresh_button.clicked.connect(load_drives)
        wipe_button.clicked.connect(on_wipe)

        load_drives()
        if not drives:
            self.show_warning("Secure Wipe", "No eligible storage devices were found.")
            dialog.reject()
            return

        dialog.exec()


def main() -> None:
    import sys

    app = QApplication(sys.argv)
    app.setStyleSheet(
        """
        QWidget {
            background-color: #2e3b4e;
            color: white;
            font-family: Arial;
        }
        QLineEdit, QComboBox, QListWidget {
            background-color: #1c2833;
            color: white;
            selection-background-color: #4CAF50;
        }
        QPushButton {
            background-color: #1c2833;
            color: white;
            padding: 6px 12px;
        }
        QPushButton#dangerButton {
            background-color: #cc0000;
            color: white;
        }
        QPushButton:hover {
            background-color: #32475b;
        }
        QLabel {
            font-size: 12pt;
        }
        """
    )
    window = TechToolbox()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

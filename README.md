# TechToolbox

TechToolbox is a PyQt6-based dashboard for Linux technicians. It combines real-time system monitoring with shortcuts to common recovery, networking, and maintenance tools.

## Features

- **Live system telemetry** – CPU, memory, swap, disk usage, uptime, fan speeds, and internal/external IP addresses are refreshed every second.
- **Launcher panel** – Start GUI applications such as GParted, GNOME Disks, Wireshark, Scrcpy, FileZilla, LibreOffice Writer, CherryTree, KeePassXC, BleachBit, Stacer, and Simple Scan.
- **Terminal helpers** – Run PhotoRec, Clonezilla, ADB device listings, Nmap scans, SMART diagnostics, network restarts, ping tests, and speed tests from a managed terminal window that keeps output open until acknowledged.
- **Recovery utilities** – Guided GNU ddrescue helper and a secure wipe workflow that performs multiple passes (0xFF, zeros, random) followed by a read-only `badblocks` verification.
- **Fan control** – Detects available PWM devices so you can push speed changes through `sudo tee` from a terminal prompt.

## Installation

1. Ensure Python 3.8+ is installed.
2. Install the Python dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Install the external tools you intend to launch (e.g., `gparted`, `wireshark`, `ddrescue`, `photorec`, `lm-sensors`, `smartmontools`, `speedtest-cli`).

## Usage

Run the dashboard from the project directory:

```bash
python3 tech_toolbox.py
```

Grant the application permission to run privileged commands when prompted (several utilities launch through `sudo` or `pkexec`).

The project previously included `linux/` and `windows/` wrappers that re-imported the top-level script; these are no longer required—`tech_toolbox.py` is the single entry point across platforms.

## Notes

- The secure wipe feature requires `lsblk`, `shred`, `badblocks`, and `pkexec`.
- Fan speed adjustments rely on writable `/sys/class/hwmon/*/pwm*` interfaces and prompt via `sudo tee`.
- External IP lookups use `requests` to call [api.ipify.org](https://api.ipify.org).
- The launchers report missing executables at startup so you can install anything that is absent from `$PATH`.

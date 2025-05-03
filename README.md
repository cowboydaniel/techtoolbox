# TechToolbox

A comprehensive technician's dashboard for Linux systems that provides real-time system monitoring and easy access to essential tools.

## Features

- Real-time system monitoring:
  - CPU usage and temperature
  - Memory usage
  - Disk usage and SMART status
  - Network speeds and IP addresses
  - Fan speed monitoring
  - System uptime

- Essential tools:
  - Disk management (GParted, GNOME Disk Utility)
  - Data recovery (PhotoRec, ddrescue)
  - Network tools (Wireshark, Speedtest, Ping)
  - File transfer (FileZilla)
  - System cleanup (BleachBit)
  - System optimization (Stacer)
  - Office tools (LibreOffice)
  - Note-taking (CherryTree)
  - Password management (KeePassXC)
  - Scanning (Simple Scan)
  - Disk diagnostics (GSmartControl)

- Quick access to system maintenance tasks:
  - Secure drive wiping
  - Network restart
  - System reboot/shutdown

## Installation

1. Run the installation script:
```bash
bash install_techtoolbox.sh
```

2. After installation completes, log out and back in for group changes to take effect

3. You can now run the application in two ways:
   - From the Applications menu (search for "TechToolbox")
   - Or from the terminal:
   ```bash
   python3 /home/outbackelectronics/TechToolbox/tech_toolbox.py
   ```

## Usage

The application provides a graphical interface with multiple tabs:

- **System Monitor**: Real-time monitoring of CPU, memory, disk, and network usage
- **Tools**: Quick access to all installed tools organized by category
- **Maintenance**: Common system maintenance tasks
- **Network**: Network diagnostics and speed testing

## Notes

- The installation script installs all required dependencies using apt
- Some tools may require additional configuration after installation
- You may need to log out and back in after running the installation script for group changes to take effect
- The application requires root privileges for some operations (e.g., disk management, network tools)
- A desktop shortcut is automatically created in your applications menu

## System Requirements

- Python 3.6+
- Linux operating system (Ubuntu/Debian recommended)
- Required system tools (automatically installed by install_tools.sh):
  - gparted
  - gnome-disk-utility
  - photorec
  - clonezilla
  - adb
  - scrcpy
  - wireshark
  - filezilla
  - bleachbit
  - stacer
  - libreoffice
  - cherrytree
  - keepassxc
  - simple-scan
  - smartmontools
  - nmap
  - lm-sensors
  - ddrescue
  - speedtest-cli
  - iputils-ping
  - gsmartcontrol

## Notes

- The installation script installs all required dependencies using apt
- Some tools may require additional configuration after installation
- You may need to log out and back in after running the installation script for group changes to take effect
- The application requires root privileges for some operations (e.g., disk management, network tools)
- A desktop shortcut is automatically created in your applications menu

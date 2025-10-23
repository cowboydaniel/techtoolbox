#!/bin/bash

# Update package list
sudo apt-get update

# Install Python dependencies
sudo apt-get install -y python3 python3-pip python3-tk

# Install system dependencies
sudo apt-get install -y \
    gparted \
    gnome-disk-utility \
    photorec \
    clonezilla \
    adb \
    scrcpy \
    wireshark \
    filezilla \
    bleachbit \
    stacer \
    libreoffice \
    cherrytree \
    keepassxc \
    simple-scan \
    smartmontools \
    nmap \
    lm-sensors \
    ddrescue \
    speedtest-cli \
    iputils-ping \
    gsmartcontrol \
    python3-psutil \
    python3-notify2

# Initialize sensors
sudo sensors-detect --auto

# Enable Wireshark to run without root
sudo groupadd wireshark
sudo usermod -a -G wireshark $USER
sudo chgrp wireshark /usr/bin/dumpcap
sudo chmod 750 /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Make the main script executable
chmod +x tech_toolbox.py

@echo off

:: Install system dependencies
powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"

:: Install Python dependencies
python -m pip install --upgrade pip
python -m venv venv

:: Activate virtual environment
call venv\Scripts\activate.bat

:: Install system dependencies using winget (Windows Package Manager)
winget install --id=Git.Git -e --source winget
winget install --id=Microsoft.VisualStudioCode -e --source winget
winget install --id=Wireshark.Wireshark -e --source winget
winget install --id=FileZilla.FileZilla -e --source winget
winget install --id=LibreOffice.LibreOffice -e --source winget
winget install --id=CherryTree.CherryTree -e --source winget
winget install --id=KeePassXCTeam.KeePassXC -e --source winget
winget install --id=Smartmontools.Smartmontools -e --source winget
winget install --id=Nmap.Nmap -e --source winget
winget install --id=SpeedtestCLI.SpeedtestCLI -e --source winget

:: Install Python dependencies
pip install -r requirements.txt

:: Make the main script executable
attrib +r tech_toolbox.py

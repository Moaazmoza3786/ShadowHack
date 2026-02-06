#!/bin/bash

# Study Hub - Pro Tools Setup Script
# Installs real security tools for the execution engine.
# Run this in your Codespace terminal: bash setup_tools.sh

echo "[*] Installing Professional Security Tools..."

# Update package lists
sudo apt-get update

# 1. Nmap (Network Mapper)
if ! command -v nmap &> /dev/null; then
    echo "[+] Installing Nmap..."
    sudo apt-get install -y nmap
else
    echo "[✓] Nmap is already installed."
fi

# 2. Whois
if ! command -v whois &> /dev/null; then
    echo "[+] Installing Whois..."
    sudo apt-get install -y whois
else
    echo "[✓] Whois is already installed."
fi

# 3. DNS Utils (dig, nslookup)
if ! command -v dig &> /dev/null; then
    echo "[+] Installing DNS Utils..."
    sudo apt-get install -y dnsutils
else
    echo "[✓] DNS Utils are already installed."
fi

# 4. Project Discovery Tools (Subfinder, Httpx) - Install via Go if possible or binary
# Checking for Go
if command -v go &> /dev/null; then
    echo "[*] Go detected. Installing ProjectDiscovery tools..."
    
    # Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo "[+] Installing Subfinder..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        # Add go bin to path if not there for this session
        export PATH=$PATH:$(go env GOPATH)/bin
    fi

    # HTTPX
    if ! command -v httpx &> /dev/null; then
        echo "[+] Installing HTTPX..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
else
    echo "[!] Go not found. Skipping Go-based tools (Subfinder, HTTPX)."
    echo "    Please install Go to enable these advanced tools."
fi

# 5. Advanced Offensive Tools (Phase 21)
echo "[*] Installing Advanced Offensive Tools..."

# SQLMap
if ! command -v sqlmap &> /dev/null; then
    echo "[+] Installing SQLMap..."
    sudo apt-get install -y sqlmap
else
    echo "[✓] SQLMap is already installed."
fi

# Nikto
if ! command -v nikto &> /dev/null; then
    echo "[+] Installing Nikto..."
    sudo apt-get install -y nikto
else
    echo "[✓] Nikto is already installed."
fi

# Hydra
if ! command -v hydra &> /dev/null; then
    echo "[+] Installing Hydra..."
    sudo apt-get install -y hydra
else
    echo "[✓] Hydra is already installed."
fi

# John the Ripper
if ! command -v john &> /dev/null; then
    echo "[+] Installing John the Ripper..."
    sudo apt-get install -y john
else
    echo "[✓] John the Ripper is already installed."
fi

# Gobuster
if ! command -v gobuster &> /dev/null; then
    echo "[+] Installing Gobuster..."
    sudo apt-get install -y gobuster
else
    echo "[✓] Gobuster is already installed."
fi

# Wordlists (Seclists / Rockyou)
if [ ! -d "/usr/share/wordlists" ]; then
    sudo mkdir -p /usr/share/wordlists
fi

if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
    echo "[+] Downloading Rockyou wordlist..."
    # Download a smaller version or the full one if feasible. Codespaces have good bandwidth.
    # Using a reliable curl source for rockyou.txt
    sudo wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /usr/share/wordlists/rockyou.txt
else
    echo "[✓] Rockyou wordlist found."
fi

# Ensure permissions
sudo chmod -R 755 /usr/share/wordlists

echo "[✓] Setup Complete! The Tool Execution Engine is ready."

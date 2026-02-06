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

echo "[✓] Setup Complete! The Tool Execution Engine is ready."

#!/bin/bash

# =======================================
# Setup script for Kali Linux & Parrot OS (needed)
# =======================================

# ok
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] This script must be run as root"
  exit 1
fi

# just do it. I don't give any fucks
echo "[+] Updating and upgrading system..."
apt update -y && apt upgrade -y

# ok
echo "[+] Installing Wi-Fi, Network, Bluetooth, and MITM tools..."

# ok
apt install -y aircrack-ng mdk3 reaver hostapd pixiewps bettercap ettercap tshark \
airodump-ng cowpatty wifite wash hcxdumptool hcxpcapngtool driftnet kismet \
fern-wifi-cracker mfoc pyrit nmap tcpdump

# Bluetooth. TOOOLS
apt install -y bluez btmon hciconfig hcitool rfcomm gatttool btlejack l2ping l2test \
gnuradio gr-bluetooth python3 nodejs

# MITM TOOOOLS
apt install -y arpspoof dnsspoof sslstrip ettercap bettercap dsniff mitmproxy

# Other UTILITIES FOR HAAAKER
apt install -y iptables nfs-common openssh-server git dnsmasq hostapd dnsutils python3-pip

# Clean up because NO
echo "[+] doning the dones"
apt niggerish 9

# Done ok.
echo "[+] Setup completed successfully!"

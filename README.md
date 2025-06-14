# ediop3Wire

## Description

**ediop3Wire** is an all-in-one network analysis and penetration testing tool designed to conduct a variety of attacks including WiFi, Bluetooth/BLE, and MITM (Man-in-the-Middle) attacks. It integrates multiple security and penetration testing tools into one powerful script, enabling security professionals and ethical hackers to perform network assessments.

## Features

### **WiFi Attacks:**
- **WPA2 Cracking**: Using tools like Aircrack, Hashcat, Pyrit, and Cowpatty for cracking WPA2 handshakes.
- **Handshake Capture & Deauthentication**: Captures WPA2 handshakes and forces disconnections for capturing new handshakes.
- **Rogue Access Point**: Create rogue APs to lure clients and steal sensitive data.
- **PMKID & WPS Cracking**: Brute-force PMKID and WPS PINs for WPA2 networks (with Reaver, Bully, PixieDust).
- **Packet Sniffing**: Real-time WiFi packet analysis and sniffing.
- **WiFi Network Discovery**: Scan nearby WiFi networks and clients.

### **Bluetooth/BLE Attacks:**
- **Bluetooth Sniffing**: Capture Bluetooth BR/EDR packets.
- **Bluetooth Low Energy (BLE) Sniffing**: Capture BLE packets and GATT enumeration.
- **Bluetooth Spoofing**: Spoof Bluetooth MAC addresses for evasion.
- **L2CAP Injection**: Inject L2CAP packets into Bluetooth connections.

### **MITM (Man-in-the-Middle) Attacks:**
- **ARP Spoofing**: Redirect network traffic using ARP poisoning.
- **DNS Spoofing**: Poison DNS responses to redirect users to malicious sites.
- **SSL Stripping**: Downgrade HTTPS connections to HTTP for sniffing.
- **Session Hijacking**: Hijack active sessions on the network.
- **Packet Tampering**: Modify packets in real-time.
- **DHCP Spoofing**: Inject malicious DHCP responses to manipulate IP assignment.

### **Network Control:**
- **Interface Management**: Bring network interfaces up/down, change MAC addresses, and enable monitor mode.
- **Route & IP Tables**: Manage network routes, change default gateways, and configure firewall rules.
- **Packet Capture**: Capture and analyze network traffic with tcpdump and Wireshark.

## Supported Platforms

- **kali linux** (Best one)
- **parrot security os** (might work)
- **Other Unix-based systems** (may require tweaks)

> **Note**: You need root privileges to run the script. Make sure you are logged in as root or use `sudo` commands.

## Installation

### **Prerequisites**

Before running the script, you must install required dechpendencies. Use the following setup script to install them.

### **Step 1: Clone the Repository**

Clone the repository from GitHub:

```bash
git clone https://github.com/ediop3SquadALT/ediop3Wire.git
cd ediop3Wire
chmod +x setup.sh && chmod +x ediop3Wire.sh
sudo ./setup.sh
sudo ./ediop3Wire.sh
```

### made by ediop3

check other repos at:
https://github.com/ediop3SquadALT


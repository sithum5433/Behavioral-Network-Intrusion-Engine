#!/usr/bin/env python3

import os
import time
import math
import threading
import urllib.request
import json
import socket
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP

# ==========================================
# Terminal Color Codes for Cyber Theme
# ==========================================
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ==========================================
# Global Data Stores
# ==========================================
flows = defaultdict(lambda: {
    'packet_count': 0,
    'ports_accessed': set(),
    'entropy_alerts': 0,
    'start_time': time.time()
})

quarantined_ips = set()
engine_running = True

# ==========================================
# Module: Heuristic/Statistical Scoring
# ==========================================
def calculate_entropy(payload):
    if not payload:
        return 0.0
    entropy = 0
    length = len(payload)
    counts = Counter(payload)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

# ==========================================
# Module: Reaction (Firewall Actions)
# ==========================================
def block_ip(ip_address, reason):
    """ Blocks IP via iptables and adds to quarantined set """
    if ip_address not in quarantined_ips:
        print(f"\n\n{Colors.RED}{Colors.BOLD}[!!!] CRITICAL THREAT DETECTED{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] REASON:{Colors.RESET} {reason}")
        print(f"{Colors.YELLOW}[!] ACTION:{Colors.RESET} Quarantining IP {Colors.RED}{ip_address}{Colors.RESET}...")
        
        os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
        quarantined_ips.add(ip_address)
        
        print(f"{Colors.GREEN}{Colors.BOLD}[+] SUCCESS: Node {ip_address} is isolated.{Colors.RESET}")
        print(f"{Colors.CYAN}DeepSight> {Colors.RESET}", end="", flush=True) # Restore prompt

# ==========================================
# Module: Investigation Engine
# ==========================================
def investigate_ip(ip_address):
    """ Fetches Geolocation, ISP, and Reverse DNS data for an IP """
    print(f"\n{Colors.MAGENTA}[*] Investigating Target: {ip_address}...{Colors.RESET}")
    
    # 1. Reverse DNS Lookup (Hostname)
    try:
        host = socket.gethostbyaddr(ip_address)
        print(f"{Colors.GREEN}  [+] Hostname:{Colors.RESET} {host[0]}")
    except:
        print(f"{Colors.YELLOW}  [-] Hostname:{Colors.RESET} No Reverse DNS record found")

    # 2. IP Geolocation and ISP Info (via free ip-api)
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        req = urllib.request.urlopen(url, timeout=5)
        data = json.loads(req.read().decode())
        
        if data['status'] == 'success':
            print(f"{Colors.GREEN}  [+] Country:{Colors.RESET}  {data.get('country')}")
            print(f"{Colors.GREEN}  [+] ISP:{Colors.RESET}      {data.get('isp')}")
            print(f"{Colors.GREEN}  [+] Org:{Colors.RESET}      {data.get('org')}")
        else:
            print(f"{Colors.YELLOW}  [-] Geolocation:{Colors.RESET} Private or Local IP Address")
    except Exception as e:
        print(f"{Colors.RED}  [-] Investigation API Error: {e}{Colors.RESET}")

# ==========================================
# Module: Packet Sniffing Logic
# ==========================================
def process_packet(packet):
    if not engine_running:
        return

    if IP in packet:
        src_ip = packet[IP].src
        if src_ip == "127.0.0.1" or src_ip.startswith("192.168.") or src_ip.startswith("10."):
            pass # You can exclude local IPs from being blocked if needed, but we keep it open for testing

        flow = flows[src_ip]
        flow['packet_count'] += 1
        
        if TCP in packet:
            flow['ports_accessed'].add(packet[TCP].dport)
        elif UDP in packet:
            flow['ports_accessed'].add(packet[UDP].dport)

        # 1. Port Scan Detection
        if len(flow['ports_accessed']) > 15:
            block_ip(src_ip, f"Port Scan (Hit {len(flow['ports_accessed'])} distinct ports)")
            return

        # 2. High Entropy Detection
        raw_payload = bytes(packet[IP].payload)
        if len(raw_payload) > 64:
            entropy_score = calculate_entropy(raw_payload)
            if entropy_score > 7.5:
                flow['entropy_alerts'] += 1
                if flow['entropy_alerts'] > 5:
                    block_ip(src_ip, f"High Entropy ({entropy_score:.2f}). Possible C2 Tunnel!")
                    return

        # 3. Traffic Flood Detection
        current_time = time.time()
        elapsed_time = current_time - flow['start_time']
        if elapsed_time > 2.0:
            if flow['packet_count'] > 500:
                block_ip(src_ip, f"Traffic Flood ({flow['packet_count']} packets in 2s)")
            
            flow['packet_count'] = 0
            flow['ports_accessed'] = set()
            flow['entropy_alerts'] = 0
            flow['start_time'] = current_time

def sniffer_thread(interface):
    """ Runs the packet sniffer in the background """
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Sniffer Error: {e}{Colors.RESET}")
        os._exit(1)

# ==========================================
# Module: Interactive CLI
# ==========================================
def print_banner(interface):
    os.system('clear')
    banner = f"""{Colors.CYAN}{Colors.BOLD}
    ██████╗ ███████╗███████╗██████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
    ██║  ██║█████╗  █████╗  ██████╔╝███████╗██║██║  ███╗███████║   ██║   
    ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ╚════██║██║██║   ██║██╔══██║   ██║   
    ██████╔╝███████╗███████╗██║     ███████║██║╚██████╔╝██║  ██║   ██║   
    ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
    {Colors.RESET}
    {Colors.MAGENTA}======================================================================{Colors.RESET}
    {Colors.YELLOW}[*] Interface :{Colors.RESET} {Colors.GREEN}{Colors.BOLD}{interface}{Colors.RESET}
    {Colors.YELLOW}[*] Engine    :{Colors.RESET} {Colors.GREEN}{Colors.BOLD}ACTIVE - Interactive Mode{Colors.RESET}
    {Colors.MAGENTA}======================================================================{Colors.RESET}
    Type {Colors.YELLOW}'help'{Colors.RESET} to see available commands.
    """
    print(banner)

def start_interactive_cli():
    """ Provides a command line interface while sniffing """
    global engine_running
    time.sleep(1) # Wait a moment for banner and sniffer to start
    
    while engine_running:
        try:
            user_input = input(f"\n{Colors.CYAN}DeepSight> {Colors.RESET}").strip().split()
            if not user_input:
                continue
            
            command = user_input[0].lower()
            
            if command == "help":
                print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
                print(f"  {Colors.YELLOW}list{Colors.RESET}               - Show all quarantined IP addresses")
                print(f"  {Colors.YELLOW}unblock <ip>{Colors.RESET}       - Remove an IP from the quarantine list")
                print(f"  {Colors.YELLOW}investigate <ip>{Colors.RESET}   - Fetch WHOIS, ISP, and Geolocation data")
                print(f"  {Colors.YELLOW}exit / quit{Colors.RESET}        - Stop the engine and exit")
            
            elif command == "list":
                print(f"\n{Colors.BOLD}[*] Quarantined IPs:{Colors.RESET}")
                if not quarantined_ips:
                    print(f"  {Colors.GREEN}No IPs currently blocked.{Colors.RESET}")
                else:
                    for ip in quarantined_ips:
                        print(f"  {Colors.RED}- {ip}{Colors.RESET}")
            
            elif command == "unblock":
                if len(user_input) < 2:
                    print(f"{Colors.RED}[!] Usage: unblock <ip_address>{Colors.RESET}")
                    continue
                target_ip = user_input[1]
                if target_ip in quarantined_ips:
                    os.system(f"iptables -D INPUT -s {target_ip} -j DROP")
                    quarantined_ips.remove(target_ip)
                    print(f"{Colors.GREEN}[+] {target_ip} has been successfully unblocked.{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[!] {target_ip} is not in the quarantine list.{Colors.RESET}")
                    
            elif command == "investigate":
                if len(user_input) < 2:
                    print(f"{Colors.RED}[!] Usage: investigate <ip_address>{Colors.RESET}")
                    continue
                investigate_ip(user_input[1])
                
            elif command in ["exit", "quit"]:
                print(f"{Colors.RED}[*] Shutting down DeepSight...{Colors.RESET}")
                engine_running = False
                os._exit(0) # Force close to kill the background sniffer thread
                
            else:
                print(f"{Colors.RED}[!] Unknown command. Type 'help' for options.{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[*] Shutting down DeepSight...{Colors.RESET}")
            os._exit(0)

if __name__ == "__main__":
    network_interface = "wlan0" 
    print_banner(network_interface)
    
    # Start the packet sniffer in a BACKGROUND thread (Daemon)
    sniffer = threading.Thread(target=sniffer_thread, args=(network_interface,), daemon=True)
    sniffer.start()
    
    # Start the Interactive CLI in the FOREGROUND
    start_interactive_cli()
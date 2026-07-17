import os
import sys
import time
import math
import threading
import urllib.request
import json
import socket
import sqlite3
import subprocess
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP

# ==========================================
# 1. Root Privilege Check
# ==========================================
if os.geteuid() != 0:
    print("\033[91m[!] FATAL: You must run DeepSight as root (sudo).\033[0m")
    sys.exit(1)

# ==========================================
# 2. Database Initialization (Persistence)
# ==========================================
# This creates a local file 'deepsight.db' to store our IPs
db_conn = sqlite3.connect('deepsight.db', check_same_thread=False)
db_cursor = db_conn.cursor()

db_cursor.execute('''CREATE TABLE IF NOT EXISTS whitelist (ip TEXT UNIQUE)''')
db_cursor.execute('''CREATE TABLE IF NOT EXISTS quarantined (ip TEXT UNIQUE)''')
db_conn.commit()

# ==========================================
# Terminal Color Codes
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
# Global Data Stores & Locks
# ==========================================
data_lock = threading.Lock()

flows = defaultdict(lambda: {
    'packet_count': 0,
    'ports_accessed': set(),
    'entropy_alerts': 0,
    'start_time': time.time()
})

# Load saved IPs from the database into RAM on startup
quarantined_ips = set(row[0] for row in db_cursor.execute('SELECT ip FROM quarantined').fetchall())
WHITELIST_IPS = set(row[0] for row in db_cursor.execute('SELECT ip FROM whitelist').fetchall())
WHITELIST_IPS.update({"8.8.8.8", "8.8.4.4"}) # Ensure defaults are always present

# Re-apply firewall rules for IPs that were saved in the database
for ip in quarantined_ips:
    subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], capture_output=True)

engine_running = True
pending_ips = {}
pending_id_counter = 1 

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

def auto_investigate(ip_address):
    info = ""
    try:
        host = socket.gethostbyaddr(ip_address)
        info += f"\n    {Colors.CYAN}[+] Hostname:{Colors.RESET} {host[0]}"
    except:
        info += f"\n    {Colors.YELLOW}[-] Hostname:{Colors.RESET} Unknown"

    try:
        url = f"http://ip-api.com/json/{ip_address}"
        req = urllib.request.urlopen(url, timeout=3)
        data = json.loads(req.read().decode())
        if data['status'] == 'success':
            info += f"\n    {Colors.CYAN}[+] Country:{Colors.RESET}  {data.get('country')}"
            info += f"\n    {Colors.CYAN}[+] ISP:{Colors.RESET}      {data.get('isp')}"
            info += f"\n    {Colors.CYAN}[+] Org:{Colors.RESET}      {data.get('org')}"
    except:
        info += f"\n    {Colors.YELLOW}[-] Geo/ISP:{Colors.RESET}  Lookup Failed"
    return info

# ==========================================
# Module: Threat Handling 
# ==========================================
def process_threat_async(ip_address, reason):
    global pending_id_counter
    investigation_data = auto_investigate(ip_address)
    
    with data_lock:
        current_id = pending_id_counter
        pending_ips[current_id] = ip_address
        pending_id_counter += 1
    
    print(f"\n\n{Colors.RED}{Colors.BOLD} [!!!] SUSPICIOUS ACTIVITY DETECTED {Colors.RESET}")
    print(f" {Colors.YELLOW}[!] Source IP:{Colors.RESET} {Colors.RED}{ip_address}{Colors.RESET}")
    print(f" {Colors.YELLOW}[!] Reason:{Colors.RESET}    {reason}")
    print(f" {Colors.MAGENTA}[*] Auto-Investigation Results:{Colors.RESET}{investigation_data}")
    print(f"\n {Colors.GREEN}[?] DECISION REQUIRED (ID: {current_id}):{Colors.RESET}")
    print(f"    Type {Colors.RED}'block {current_id}'{Colors.RESET} to quarantine this IP.")
    print(f"    Type {Colors.YELLOW}'ignore {current_id}'{Colors.RESET} to whitelist it.")
    print(f"\n{Colors.CYAN}DeepSight> {Colors.RESET}", end="", flush=True)

def handle_threat(ip_address, reason):
    with data_lock:
        if ip_address in quarantined_ips or ip_address in WHITELIST_IPS or ip_address in pending_ips.values():
            return
    threading.Thread(target=process_threat_async, args=(ip_address, reason), daemon=True).start()

# ==========================================
# Module: Packet Sniffing Logic
# ==========================================
def process_packet(packet):
    if not engine_running:
        return
    if IP in packet:
        src_ip = packet[IP].src
        
        with data_lock:
            if (src_ip in WHITELIST_IPS or src_ip.startswith("127.") or 
                src_ip.startswith("192.168.") or src_ip.startswith("10.")):
                return
            flow = flows[src_ip]
            flow['packet_count'] += 1
            
            if TCP in packet:
                flow['ports_accessed'].add(packet[TCP].dport)
            elif UDP in packet:
                flow['ports_accessed'].add(packet[UDP].dport)

        if len(flow['ports_accessed']) > 15:
            handle_threat(src_ip, f"Port Scan (Hit {len(flow['ports_accessed'])} ports)")
            return

        raw_payload = bytes(packet[IP].payload)
        if len(raw_payload) > 64:
            entropy_score = calculate_entropy(raw_payload)
            if entropy_score > 7.5:
                with data_lock:
                    flow['entropy_alerts'] += 1
                    alerts = flow['entropy_alerts']
                if alerts > 5:
                    handle_threat(src_ip, f"High Entropy ({entropy_score:.2f}). Possible C2 Tunnel!")
                    return

        current_time = time.time()
        elapsed_time = current_time - flow['start_time']
        
        if elapsed_time > 2.0:
            if flow['packet_count'] > 500:
                handle_threat(src_ip, f"Traffic Flood ({flow['packet_count']} packets in 2s)")
            with data_lock:
                flow['packet_count'] = 0
                flow['ports_accessed'] = set()
                flow['entropy_alerts'] = 0
                flow['start_time'] = current_time

def sniffer_thread(interface):
    try:
        # 3. Kernel-Level Filtering: BPF filter applied here to drop non-IP traffic early
        sniff(iface=interface, filter="ip and (tcp or udp)", prn=process_packet, store=False)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Sniffer Error: {e}{Colors.RESET}")
        os._exit(1)

# ==========================================
# Module: Interactive CLI Data Parser
# ==========================================
def resolve_target(user_input_arg):
    with data_lock:
        if user_input_arg.isdigit():
            target_id = int(user_input_arg)
            if target_id in pending_ips:
                return pending_ips.pop(target_id)
            else:
                return None
        else:
            target_ip = user_input_arg
            keys_to_delete = [k for k, v in pending_ips.items() if v == target_ip]
            for k in keys_to_delete:
                del pending_ips[k]
            return target_ip

# ==========================================
# Module: Interactive CLI
# ==========================================
def print_banner(interface):
    subprocess.run(['clear'])
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
    {Colors.YELLOW}[*] Engine    :{Colors.RESET} {Colors.GREEN}{Colors.BOLD}ACTIVE - Database Persistent{Colors.RESET}
    {Colors.MAGENTA}======================================================================{Colors.RESET}
    Type {Colors.YELLOW}'help'{Colors.RESET} to see available commands.
    """
    print(banner)

def start_interactive_cli():
    global engine_running
    time.sleep(1) 
    
    while engine_running:
        try:
            user_input = input(f"\n{Colors.CYAN}DeepSight> {Colors.RESET}").strip().split()
            if not user_input:
                continue
            
            command = user_input[0].lower()
            
            if command == "help":
                print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
                print(f"  {Colors.YELLOW}list{Colors.RESET}             - Show all quarantined IPs")
                print(f"  {Colors.YELLOW}pending{Colors.RESET}          - Show IPs waiting for your decision")
                print(f"  {Colors.YELLOW}block <id/ip>{Colors.RESET}    - Quarantine by Alert ID or IP")
                print(f"  {Colors.YELLOW}ignore <id/ip>{Colors.RESET}   - Whitelist by Alert ID or IP")
                print(f"  {Colors.YELLOW}unblock <ip>{Colors.RESET}     - Remove an IP from quarantine")
                print(f"  {Colors.YELLOW}exit / quit{Colors.RESET}      - Stop the engine")
            
            elif command == "pending":
                print(f"\n{Colors.BOLD}[*] Pending Decisions:{Colors.RESET}")
                with data_lock:
                    if not pending_ips:
                        print(f"  {Colors.GREEN}No pending alerts.{Colors.RESET}")
                    else:
                        for alert_id, ip in pending_ips.items():
                            print(f"  {Colors.YELLOW}[ID: {alert_id}] - {ip}{Colors.RESET}")
                        
            elif command == "list":
                print(f"\n{Colors.BOLD}[*] Quarantined IPs:{Colors.RESET}")
                with data_lock:
                    if not quarantined_ips:
                        print(f"  {Colors.GREEN}No IPs currently blocked.{Colors.RESET}")
                    else:
                        for ip in quarantined_ips:
                            print(f"  {Colors.RED}- {ip}{Colors.RESET}")
            
            elif command == "block":
                if len(user_input) < 2:
                    continue
                target_ip = resolve_target(user_input[1])
                
                if target_ip:
                    # SECURE EXECUTION: Using subprocess list format prevents command injection
                    subprocess.run(["iptables", "-I", "INPUT", "1", "-s", target_ip, "-j", "DROP"], capture_output=True)
                    with data_lock:
                        quarantined_ips.add(target_ip)
                        # Save to Database
                        db_cursor.execute("INSERT OR IGNORE INTO quarantined (ip) VALUES (?)", (target_ip,))
                        db_conn.commit()
                    print(f"{Colors.GREEN}[+] SUCCESS: {target_ip} blocked and saved to DB.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[!] Invalid ID.{Colors.RESET}")
            
            elif command == "ignore":
                if len(user_input) < 2:
                    continue
                target_ip = resolve_target(user_input[1])
                
                if target_ip:
                    with data_lock:
                        WHITELIST_IPS.add(target_ip)
                        # Save to Database
                        db_cursor.execute("INSERT OR IGNORE INTO whitelist (ip) VALUES (?)", (target_ip,))
                        db_conn.commit()
                    print(f"{Colors.GREEN}[+] {target_ip} added to Whitelist in DB.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[!] Invalid ID.{Colors.RESET}")
                
            elif command == "unblock":
                if len(user_input) < 2:
                    continue
                target_ip = user_input[1]
                
                with data_lock:
                    is_blocked = target_ip in quarantined_ips
                    
                if is_blocked:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"], capture_output=True)
                    with data_lock:
                        quarantined_ips.remove(target_ip)
                        # Remove from Database
                        db_cursor.execute("DELETE FROM quarantined WHERE ip = ?", (target_ip,))
                        db_conn.commit()
                    print(f"{Colors.GREEN}[+] {target_ip} has been unblocked and removed from DB.{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[!] {target_ip} is not currently blocked.{Colors.RESET}")
                
            elif command in ["exit", "quit"]:
                print(f"{Colors.RED}[*] Shutting down DeepSight...{Colors.RESET}")
                engine_running = False
                db_conn.close()
                os._exit(0) 
                
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[*] Shutting down DeepSight...{Colors.RESET}")
            db_conn.close()
            os._exit(0)

if __name__ == "__main__":
    network_interface = "wlan0" 
    print_banner(network_interface)
    
    sniffer = threading.Thread(target=sniffer_thread, args=(network_interface,), daemon=True)
    sniffer.start()
    
    start_interactive_cli()

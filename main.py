import os
import sys
import time
import json
import random
import socket
import hashlib
import threading
import subprocess
import ipaddress
from datetime import datetime
from getpass import getpass
import re
import uuid
import platform
import colorama
from colorama import Fore, Back, Style
import pyotp
import logging
import time
import sys  # For exiting on failure

# Example user database with MFA secrets (this would normally be stored securely)
users_db = {
    'user': {'password': 'user123', 'secret': 'JBSWY3DPEHPK3PXP', "role": "user"},  # MFA secret
    'admin': {'password': 'admin123', 'secret': 'KVKFKRCPNZQUYMLX', "role": "admin"},
    'soc': {'password': 'soc123', 'secret': 'X2XKM3DFNZTSA5LS', 'role': 'soc_analyst'}
}

# Log file setup for tracking user activities
logging.basicConfig(filename='access_logs.log', level=logging.INFO)

# Function to log user activity
def log_activity(user, event):
    logging.info(f"{user} performed {event} at {time.ctime()}")

# Function to authenticate the user (username and password)
def authenticate_user(username, password):
    if username not in users_db:
        print("❌ User not found!")
        log_activity(username, 'Login failed - user not found')
        return None
    user = users_db[username]
    if password == user['password']:
        return user
    else:
        print("❌ Invalid password!")
        log_activity(username, 'Login failed - wrong password')
        return None

# Function to verify the OTP entered by the user
def validate_otp(user_secret, username):
    totp = pyotp.TOTP(user_secret)  # Create OTP object using user secret
    print("🔐 Your OTP (for testing only):", totp.now())  # Show OTP for testing
    otp = input("Enter OTP: ")  # Prompt for OTP
    if totp.verify(otp, valid_window=1):  # Allow ±30 seconds drift
        return True
    else:
        print("❌ Invalid OTP.")
        log_activity(username, 'MFA failed - invalid OTP')
        return False

# Main logic for authentication + MFA and then proceeding with your project
def authenticate_and_proceed():
    username = input("Enter username: ")
    password = input("Enter password: ")

    # Step 1: Authenticate user
    user = authenticate_user(username, password)
    if not user:
        print("❌ Authentication failed. Access denied.")
        sys.exit()

    print(f"✅ Authentication successful for {username}")
    log_activity(username, 'Login successful')

    # Step 2: Validate OTP
    if not validate_otp(user['secret'], username):
        print("❌ MFA verification failed. Access denied.")
        sys.exit()

    print("✅ MFA verification successful! Access granted.")
    log_activity(username, 'MFA successful')

    # Step 3: Run the main project
    proceed_with_project()

# Dummy project function after successful MFA
def proceed_with_project():
    print("🚀 Proceeding with project operations...")
    perform_sensitive_task()

# Sensitive task simulation
def perform_sensitive_task():
    print("🔐 Performing sensitive task...")

# Start the program
if __name__ == '__main__':
    authenticate_and_proceed()

# Third-party imports that handle real-time system data
try:
    import psutil
    import scapy.all as scapy
    from scapy.layers import http
    import pyperclip
except ImportError:
    print(f"{Fore.RED}Missing required packages. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "psutil", "scapy", "pyperclip"])
    import psutil
    import scapy.all as scapy
    from scapy.layers import http
    import pyperclip

# Initialize colorama
colorama.init(autoreset=True)

# File to store account data
DATA_FILE = "cyber_sim_data.json"

# Default data structure if file doesn't exist
DEFAULT_DATA = {
    "accounts": {
        "admin": {"password": "admin123", "mfa_secret": "123456", "role": "admin"},
        "user": {"password": "user123", "mfa_secret": "654321", "role": "user"},
        "soc": {"password": "soc123", "mfa_secret": "246810", "role": "soc_analyst"}
    },
    "firewall_rules": [
        {"id": 1, "source": "192.168.1.0/24", "destination": "ANY", "port": "80,443", "action": "ALLOW"},
        {"id": 2, "source": "ANY", "destination": "192.168.1.100", "port": "22", "action": "DENY"},
    ],
    "known_mac_addresses": {},
    "file_hashes": {},
    "threat_logs": [],
    "clipboard_history": []
}

# Global variables
current_user = None
scanning = False
sniffing = False
monitoring = False
honeypot_running = False
file_watcher_running = False
hash_checker_running = False
log_visualizer_running = False
insider_tracker_running = False
stop_threads = False

def load_data():
    """Load data from JSON file or create default if not exists"""
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as file:
                return json.load(file)
        else:
            save_data(DEFAULT_DATA)
            return DEFAULT_DATA
    except Exception as e:
        print(f"{Fore.RED}Error loading data: {e}")
        return DEFAULT_DATA

def save_data(data):
    """Save data to JSON file"""
    try:
        with open(DATA_FILE, 'w') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"{Fore.RED}Error saving data: {e}")

def log_threat(threat_type, details, severity=None):
    """Log a threat to the data file"""
    data = load_data()
    if not severity:
        severity = random.choice(["Low", "Medium", "High", "Critical"])
    
    threat = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": threat_type,
        "details": details,
        "severity": severity
    }
    data["threat_logs"].append(threat)
    
    # Keep only the last 100 logs to prevent file growth
    if len(data["threat_logs"]) > 100:
        data["threat_logs"] = data["threat_logs"][-100:]
    
    save_data(data)
    return threat

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print a fancy banner for the cybersecurity toolkit"""
    clear_screen()
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║ {Fore.RED}Z{Fore.GREEN}E{Fore.BLUE}R{Fore.YELLOW}O {Fore.MAGENTA}T{Fore.CYAN}R{Fore.WHITE}U{Fore.RED}S{Fore.GREEN}T {Fore.BLUE}C{Fore.YELLOW}Y{Fore.MAGENTA}B{Fore.CYAN}E{Fore.WHITE}R{Fore.RED}S{Fore.GREEN}E{Fore.BLUE}C{Fore.YELLOW}U{Fore.MAGENTA}R{Fore.CYAN}I{Fore.WHITE}T{Fore.RED}Y {Fore.GREEN}T{Fore.BLUE}O{Fore.YELLOW}O{Fore.MAGENTA}L{Fore.CYAN}K{Fore.WHITE}I{Fore.RED}T       {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Fore.YELLOW}[*] Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.YELLOW}[*] System: {platform.system()} {platform.release()}")
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        print(f"{Fore.YELLOW}[*] Host: {hostname} ({ip_address})")
    except:
        print(f"{Fore.YELLOW}[*] Host: Unable to determine")
    print(f"{Fore.YELLOW}[*] Zero Trust Framework Active{Fore.RESET}")
    print()

def get_interfaces():
    """Get all network interfaces on the system"""
    interfaces = {}
    try:
        # Iterate over network interfaces
        for iface_name, iface_addresses in psutil.net_if_addrs().items():
            for addr in iface_addresses:
                if addr.family == 2:  # AF_INET (IPv4)
                    ip = addr.address
                    # Skip loopback
                    if ip.startswith('127.'):
                        continue
                    interfaces[iface_name] = ip
    except Exception as e:
        print(f"Error occurred: {e}")
        interfaces["eth0"] = "192.168.1.100"  # Fallback
    
    return interfaces

def mfa_bruteforce():
    """Simulate MFA bruteforce with real-time visualization"""
    data = load_data()
    accounts = list(data["accounts"].keys())
    
    print(f"{Fore.YELLOW}[*] Available accounts: {', '.join(accounts)}")
    account = input(f"{Fore.GREEN}[+] Enter account name to bruteforce: ")
    
    if account not in data["accounts"]:
        print(f"{Fore.RED}[!] Account not found!")
        return
    
    print(f"{Fore.YELLOW}[*] Starting MFA bruteforce for {account}...")
    print(f"{Fore.YELLOW}[*] Using intelligent brute force algorithm")
    
    # Simulating MFA code attempt with visual feedback
    correct_mfa = data["accounts"][account]["mfa_secret"]
    attempt_count = 0
    max_attempts = random.randint(5, 15)  # Random number of attempts before "success"
    
    # Show progress with real MFA digits
    for i in range(max_attempts):
        attempt_count += 1
        
        # Generate a code that's closer to the correct one as we progress
        if i > max_attempts * 0.7:  # Last 30% of attempts
            # Generate code with some digits correct
            test_mfa = ""
            for j in range(len(correct_mfa)):
                if random.random() < 0.7:  # 70% chance to get this digit right
                    test_mfa += correct_mfa[j]
                else:
                    test_mfa += str(random.randint(0, 9))
        else:
            # Random code
            test_mfa = ''.join([str(random.randint(0, 9)) for _ in range(len(correct_mfa))])
        
        print(f"{Fore.CYAN}[*] Attempt {attempt_count}: Testing code {test_mfa[:2]}{'*' * (len(test_mfa)-2)}", end="")
        sys.stdout.flush()
        
        # Add real delay to simulate actual network traffic
        time.sleep(random.uniform(0.2, 0.5))
        
        # Log attempt
        log_threat("MFA Bruteforce", f"Attempt on account '{account}' with code {test_mfa[:2]}**...")
        
        if test_mfa == correct_mfa or i == max_attempts - 1:
            print(f"\r{Fore.GREEN}[+] SUCCESS! MFA code found: {correct_mfa}")
            print(f"{Fore.GREEN}[+] Account {account} compromised after {attempt_count} attempts")
            log_threat("MFA Bruteforce", f"SUCCESS: Account '{account}' compromised", "Critical")
            break
        else:
            print(f"\r{Fore.RED}[!] Failed with code {test_mfa[:2]}{'*' * (len(test_mfa)-2)}")
            
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def scan_ports(target_ip):
    """Scan open ports on a target IP address"""
    global scanning, stop_threads
    scanning = True
    
    # Validate IP
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"{Fore.RED}[!] Invalid IP address")
        scanning = False
        return
    
    print(f"{Fore.YELLOW}[*] Starting port scan on {target_ip}")
    print(f"{Fore.YELLOW}[*] Scanning common ports...")
    
    # Common vulnerable ports
    common_ports = {
        21: "FTP", 
        22: "SSH", 
        23: "Telnet", 
        25: "SMTP", 
        53: "DNS",
        80: "HTTP", 
        110: "POP3", 
        135: "MS-RPC", 
        139: "NetBIOS", 
        143: "IMAP",
        443: "HTTPS", 
        445: "SMB", 
        1433: "MSSQL", 
        3306: "MySQL", 
        3389: "RDP",
        5900: "VNC", 
        8080: "HTTP-Proxy"
    }
    
    found_ports = []
    total_ports = len(common_ports)
    scanning_thread = None
    
    def scan_worker():
        nonlocal found_ports
        count = 0
        for port, service in common_ports.items():
            if stop_threads:
                break
                
            count += 1
            print(f"\r{Fore.YELLOW}[*] Progress: {count}/{total_ports} ports checked", end="")
            
            # Try to connect to the port with real socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((target_ip, port))
                s.close()
                
                if result == 0:
                    found_ports.append((port, service))
                    print(f"\r{Fore.GREEN}[+] Port {port} ({service}) is OPEN{' ' * 30}")
                    # Log the finding as a potential threat
                    log_threat("Port Scan", f"Open port found on {target_ip}: {port}/{service}")
                    
            except socket.error:
                pass
                
            # Add realistic delay to respect network
            time.sleep(0.1)
        
        print(f"\r{Fore.YELLOW}[*] Scan completed. {len(found_ports)} open ports found.{' ' * 30}")
    
    try:
        scanning_thread = threading.Thread(target=scan_worker)
        scanning_thread.daemon = True
        scanning_thread.start()
        
        # Wait for scan to complete or user to cancel
        while scanning_thread.is_alive():
            time.sleep(0.1)
            if msvcrt_available():
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b'q':
                        stop_threads = True
                        print(f"\n{Fore.RED}[!] Scan cancelled by user")
                        break
            
        if found_ports:
            print(f"\n{Fore.GREEN}[+] Open ports summary:")
            for port, service in found_ports:
                print(f"{Fore.GREEN}[+] {port}/TCP - {service}")
        else:
            print(f"\n{Fore.YELLOW}[*] No open ports found on {target_ip}")
            
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during port scan: {e}")
    finally:
        scanning = False
        stop_threads = False
        
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def msvcrt_available():
    """Check if msvcrt is available (Windows only)"""
    try:
        import msvcrt
        return True
    except ImportError:
        return False

def packet_sniffer():
    """Sniff packets on the network in real-time"""
    global sniffing, stop_threads
    
    def process_packet(packet):
        """Process a captured packet and display relevant info"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            
            # Resolve protocol number to name
            proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else f"Proto:{proto}"
            
            # Check for common application protocols
            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                
                # HTTP detection
                if src_port == 80 or dst_port == 80:
                    app_proto = "HTTP"
                # HTTPS detection
                elif src_port == 443 or dst_port == 443:
                    app_proto = "HTTPS"
                # SSH detection
                elif src_port == 22 or dst_port == 22:
                    app_proto = "SSH"
                # SMTP detection
                elif src_port == 25 or dst_port == 25:
                    app_proto = "SMTP"
                else:
                    app_proto = f"TCP {src_port}->{dst_port}"
                    
                # Mark suspicious ports in red
                suspicious_ports = [1433, 3306, 3389, 5900, 8080]
                color = Fore.RED if (src_port in suspicious_ports or dst_port in suspicious_ports) else Fore.GREEN
                
                print(f"{Fore.CYAN}[{timestamp}] {color}{proto_name}/{app_proto}: {src_ip} -> {dst_ip}")
                
                # Look for HTTP data
                if packet.haslayer(http.HTTPRequest):
                    url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                    method = packet[http.HTTPRequest].Method.decode()
                    print(f"{Fore.YELLOW}[HTTP] {method} {url}")
                    
                    # Look for credentials in POST requests
                    if packet.haslayer(scapy.Raw) and method == "POST":
                        load = packet[scapy.Raw].load.decode(errors='ignore')
                        keywords = ['username', 'user', 'login', 'password', 'pass', 'email']
                        for keyword in keywords:
                            if keyword in load.lower():
                                print(f"{Fore.RED}[!] Possible credentials in POST: {load}")
                                log_threat("Packet Sniffing", f"Possible credentials detected: {load}", "High")
                                break
            
            # UDP traffic
            elif packet.haslayer(scapy.UDP):
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                app_proto = f"UDP {src_port}->{dst_port}"
                
                # DNS detection
                if src_port == 53 or dst_port == 53:
                    app_proto = "DNS"
                
                print(f"{Fore.CYAN}[{timestamp}] {Fore.BLUE}{proto_name}/{app_proto}: {src_ip} -> {dst_ip}")
    
    # Get interfaces
    interfaces = get_interfaces()
    
    if not interfaces:
        print(f"{Fore.RED}[!] No network interfaces found")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")
        return
        
    print(f"{Fore.YELLOW}[*] Available network interfaces:")
    for idx, (iface, ip) in enumerate(interfaces.items(), 1):
        print(f"{Fore.GREEN}[{idx}] {iface} - {ip}")
    
    try:
        choice = int(input(f"{Fore.YELLOW}[*] Select interface (number): "))
        if choice < 1 or choice > len(interfaces):
            print(f"{Fore.RED}[!] Invalid choice")
            return
            
        iface = list(interfaces.keys())[choice-1]
    except ValueError:
        print(f"{Fore.RED}[!] Invalid input")
        return
        
    print(f"{Fore.YELLOW}[*] Starting packet sniffer on {iface} ({interfaces[iface]})")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop sniffing")
    print(f"{Fore.YELLOW}[*] Capturing packets in real-time...\n")
    
    sniffing = True
    stop_threads = False
    
    try:
        # Start actual packet capture
        scapy.sniff(iface=iface, prn=process_packet, store=False, 
                   stop_filter=lambda x: stop_threads)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"{Fore.RED}[!] Error while sniffing: {e}")
    finally:
        sniffing = False
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Packet sniffing stopped")
        log_threat("Network Monitoring", f"Packet sniffing performed on {iface}", "Low")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def mac_spoof_detector():
    """Detect MAC address spoofing based on real network data"""
    global monitoring, stop_threads
    
    def get_current_macs():
        """Get all MAC addresses on the network using ARP scan"""
        print(f"{Fore.YELLOW}[*] Scanning for MAC addresses on local network...")
        
        # Use real system network data
        macs = {}
        interfaces = get_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}[!] No network interfaces found")
            return {}
            
        # Use the first valid interface for scanning
        iface = list(interfaces.keys())[0]
        ip = interfaces[iface]
        
        # Get subnet for scanning
        ip_parts = ip.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        try:
            # Perform ARP scan using scapy
            print(f"{Fore.YELLOW}[*] Scanning subnet {subnet}...")
            ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=subnet), 
                              timeout=3, verbose=0, iface=iface)
            
            # Process results
            for sent, received in ans:
                mac = received.hwsrc
                ip = received.psrc
                macs[mac] = ip
                print(f"{Fore.GREEN}[+] Found {ip} with MAC {mac}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] ARP scan error: {e}")
            # Use demo data if real scan fails
            macs = {
                "00:11:22:33:44:55": "192.168.1.1",
                "aa:bb:cc:dd:ee:ff": "192.168.1.100",
                "11:22:33:44:55:66": "192.168.1.101"
            }
            for mac, ip in macs.items():
                print(f"{Fore.GREEN}[+] Found {ip} with MAC {mac}")
        
        return macs
    
    monitoring = True
    stop_threads = False
    data = load_data()
    
    # Get current MAC addresses
    current_macs = get_current_macs()
    
    if not current_macs:
        print(f"{Fore.RED}[!] No MAC addresses found")
        monitoring = False
        return
    
    # Compare with known MACs
    print(f"\n{Fore.YELLOW}[*] Analyzing for potential MAC spoofing...")
    
    # Update known MACs if empty
    if not data["known_mac_addresses"]:
        print(f"{Fore.YELLOW}[*] No known MAC addresses in database, adding current ones as trusted...")
        data["known_mac_addresses"] = {
            mac: f"Device at {ip}" for mac, ip in current_macs.items()
        }
        save_data(data)
    
    # Check for unknown or changed MACs
    unknown_macs = []
    for mac, ip in current_macs.items():
        if mac not in data["known_mac_addresses"]:
            unknown_macs.append((mac, ip))
            print(f"{Fore.RED}[!] Unknown MAC detected: {mac} at {ip}")
            log_threat("MAC Spoofing", f"Unknown MAC address detected: {mac} at {ip}", "High")
        
    if not unknown_macs:
        print(f"{Fore.GREEN}[+] No unknown MAC addresses detected")
    else:
        print(f"\n{Fore.YELLOW}[*] Found {len(unknown_macs)} unknown MAC addresses")
        
        # Ask to add them to trusted list
        choice = input(f"{Fore.YELLOW}[?] Add these MACs to trusted list? (y/n): ")
        if choice.lower() == 'y':
            for mac, ip in unknown_macs:
                data["known_mac_addresses"][mac] = f"Device at {ip}"
            save_data(data)
            print(f"{Fore.GREEN}[+] Added unknown MACs to trusted list")
    
    monitoring = False
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def soc_dashboard():
    """Display a SOC-style threat dashboard with real-time updates"""
    global stop_threads
    stop_threads = False
    
    # Function to generate real system metrics
    def get_system_metrics():
        metrics = {}
        # CPU usage
        metrics["cpu"] = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        mem = psutil.virtual_memory()
        metrics["memory"] = mem.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        metrics["disk"] = disk.percent
        
        # Network connections
        connections = len(psutil.net_connections())
        metrics["connections"] = connections
        
        return metrics
    
    # Generate random attack data
    def generate_attack_data():
        attack_types = ["Brute Force", "SQL Injection", "XSS", "DDOS", "Data Exfiltration"]
        sources = ["45.227.253." + str(random.randint(1, 254)),
                   "103.102.166." + str(random.randint(1, 254)),
                   "185.156.73." + str(random.randint(1, 254)),
                   "192.168.1." + str(random.randint(1, 254))]
        
        return {
            "type": random.choice(attack_types),
            "source": random.choice(sources),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "severity": random.choice(["Low", "Medium", "High", "Critical"])
        }
    
    # Load existing threats
    data = load_data()
    threats = data["threat_logs"][-10:] if data["threat_logs"] else []
    
    # Add some real-time generated threats if needed
    if len(threats) < 5:
        for _ in range(5 - len(threats)):
            attack = generate_attack_data()
            threats.append({
                "timestamp": attack["timestamp"],
                "type": attack["type"],
                "details": f"Attack from {attack['source']}",
                "severity": attack["severity"]
            })
    
    # Dashboard loop
    refresh_interval = 1.0  # seconds
    start_time = datetime.now()
    iteration = 0
    
    try:
        while not stop_threads:
            clear_screen()
            current_time = datetime.now()
            uptime = (current_time - start_time).seconds
            
            # Get real-time system metrics
            metrics = get_system_metrics()
            
            # Header
            print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"{Fore.CYAN}║ {Fore.YELLOW}ZERO TRUST SECURITY OPERATIONS CENTER - REAL-TIME DASHBOARD{' ' * 26}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Current Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')} | Dashboard Uptime: {uptime}s{' ' * 10}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            # System metrics
            cpu_bar = "█" * int(metrics["cpu"] / 5)
            mem_bar = "█" * int(metrics["memory"] / 5)
            disk_bar = "█" * int(metrics["disk"] / 5)
            
            cpu_color = Fore.GREEN if metrics["cpu"] < 70 else Fore.YELLOW if metrics["cpu"] < 90 else Fore.RED
            mem_color = Fore.GREEN if metrics["memory"] < 70 else Fore.YELLOW if metrics["memory"] < 90 else Fore.RED
            disk_color = Fore.GREEN if metrics["disk"] < 70 else Fore.YELLOW if metrics["disk"] < 90 else Fore.RED
            conn_color = Fore.GREEN if metrics["connections"] < 100 else Fore.YELLOW if metrics["connections"] < 200 else Fore.RED
            
            print(f"{Fore.CYAN}║ {Fore.WHITE}System Metrics:{' ' * 62}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}CPU Usage:  {cpu_color}{metrics['cpu']:3.1f}% {cpu_bar}{' ' * (20 - len(cpu_bar))}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Memory:     {mem_color}{metrics['memory']:3.1f}% {mem_bar}{' ' * (20 - len(mem_bar))}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Disk:       {disk_color}{metrics['disk']:3.1f}% {disk_bar}{' ' * (20 - len(disk_bar))}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Connections: {conn_color}{metrics['connections']}{' ' * 57}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            # Threat summary
            severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
            for threat in threats:
                severity_counts[threat["severity"]] += 1
            
            print(f"{Fore.CYAN}║ {Fore.WHITE}Threat Summary:{' ' * 61}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Low: {severity_counts['Low']:2d} | {Fore.YELLOW}Medium: {severity_counts['Medium']:2d} | {Fore.RED}High: {severity_counts['High']:2d} | {Fore.MAGENTA}Critical: {severity_counts['Critical']:2d}{' ' * 30}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            # Recent threats
            print(f"{Fore.CYAN}║ {Fore.WHITE}Recent Threats:{' ' * 62}{Fore.CYAN}║")
            
            # Add a new threat every few iterations
            iteration += 1
            if iteration % 3 == 0:
                attack = generate_attack_data()
                new_threat = {
                    "timestamp": attack["timestamp"],
                    "type": attack["type"],
                    "details": f"Attack from {attack['source']}",
                    "severity": attack["severity"]
                }
                threats.append(new_threat)
                threats = threats[-10:]  # Keep only the last 10
                log_threat(attack["type"], f"Attack from {attack['source']}", attack["severity"])
            
            # Show last 5 threats
            for i, threat in enumerate(threats[-5:]):
                severity_color = (Fore.GREEN if threat["severity"] == "Low" else
                                 Fore.YELLOW if threat["severity"] == "Medium" else
                                 Fore.RED if threat["severity"] == "High" else
                                 Fore.MAGENTA)
                
                print(f"{Fore.CYAN}║ {severity_color}[{threat['severity']}] {threat['timestamp']} - {threat['type']}: {threat['details'][:40]}{' ' * (13 - len(threat['details'][:40]))}{Fore.CYAN}║")
            
            if len(threats[-5:]) < 5:
                for _ in range(5 - len(threats[-5:])):
                    print(f"{Fore.CYAN}║{' ' * 78}{Fore.CYAN}║")
            
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Press Ctrl+C to return to main menu{' ' * 46}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
            
            time.sleep(refresh_interval)
            
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Dashboard stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def honeypot():
    """Deploy a fake SSH honeypot to detect and monitor intrusion attempts"""
    global honeypot_running, stop_threads
    
    print(f"{Fore.YELLOW}[*] Setting up SSH honeypot...")
    
    # Get local IP address
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "192.168.1.100"  # Fallback
    
    # Ask for port
    try:
        port = int(input(f"{Fore.YELLOW}[*] Enter port to deploy honeypot (default: 22): ") or "22")
    except ValueError:
        port = 22
        print(f"{Fore.RED}[!] Invalid port, using default port 22")
    
    print(f"{Fore.GREEN}[+] Deploying honeypot on {local_ip}:{port}")
    print(f"{Fore.YELLOW}[*] Starting SSH honeypot server...")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop the honeypot\n")
    
    honeypot_running = True
    stop_threads = False
    connection_count = 0
    
    # Create a fake server socket
    def honeypot_server():
        nonlocal connection_count
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.settimeout(1)  # Set timeout for non-blocking operation
            server.listen(5)
            
            print(f"{Fore.GREEN}[+] Honeypot listening on port {port}")
            
            while not stop_threads:
                try:
                    client, addr = server.accept()
                    connection_count += 1
                    threading.Thread(target=handle_client, args=(client, addr)).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"{Fore.RED}[!] Server error: {e}")
                    break
                    
            server.close()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Could not start honeypot: {e}")
            if "Permission denied" in str(e):
                print(f"{Fore.RED}[!] You need root/admin privileges to bind to port {port}")
            elif "Address already in use" in str(e):
                print(f"{Fore.RED}[!] Port {port} is already in use")
    
    # Handle incoming connections
    def handle_client(client_socket, address):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Fore.RED}[!] Connection from {address[0]}:{address[1]} at {timestamp}")
        
        # Log the connection attempt
        log_threat("Honeypot", f"Connection attempt from {address[0]}:{address[1]}", "Medium")
        
        # Send SSH banner
        client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")
        
        # Wait for credentials
        try:
            # Set a timeout for receiving data
            client_socket.settimeout(10)
            
            # Receive username
            client_socket.send(b"login as: ")
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Receive password
            client_socket.send(f"{username}@{hostname}'s password: ".encode())
            password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Log the attempted credentials
            print(f"{Fore.RED}[!] Login attempt - Username: {username}, Password: {'*' * len(password)}")
            log_threat("Honeypot", f"Login attempt with credentials - User: {username}, Pass: {password}", "High")
            
            # Simulate authentication failure
            client_socket.send(b"Access denied\r\n")
            time.sleep(1)
            
        except Exception as e:
            pass
            
        # Close connection
        try:
            client_socket.close()
        except:
            pass
    
    # Start honeypot thread
    honeypot_thread = threading.Thread(target=honeypot_server)
    honeypot_thread.daemon = True
    honeypot_thread.start()
    
    # Display honeypot activity
    try:
        start_time = datetime.now()
        last_count = 0
        
        while honeypot_thread.is_alive() and not stop_threads:
            current_time = datetime.now()
            uptime = (current_time - start_time).seconds
            
            # Only update display if there are new connections
            if connection_count > last_count:
                clear_screen()
                print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}SSH HONEYPOT - INTRUSION DETECTION{' ' * 49}{Fore.CYAN}║")
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                print(f"{Fore.CYAN}║ {Fore.GREEN}Listening on: {local_ip}:{port}{' ' * 57}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.GREEN}Uptime: {uptime} seconds{' ' * 61}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.GREEN}Connection attempts: {connection_count}{' ' * 55}{Fore.CYAN}║")
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                
                # Load recent logs related to honeypot
                data = load_data()
                honeypot_logs = [log for log in data["threat_logs"] if "Honeypot" in log["type"]][-5:]
                
                print(f"{Fore.CYAN}║ {Fore.WHITE}Recent Activity:{' ' * 63}{Fore.CYAN}║")
                
                for log in honeypot_logs:
                    details = log["details"]
                    if len(details) > 60:
                        details = details[:57] + "..."
                    print(f"{Fore.CYAN}║ {Fore.RED}{log['timestamp']}: {details}{' ' * (53 - len(details))}{Fore.CYAN}║")
                    
                # Fill empty lines
                for _ in range(5 - len(honeypot_logs)):
                    print(f"{Fore.CYAN}║{' ' * 78}{Fore.CYAN}║")
                    
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                print(f"{Fore.CYAN}║ {Fore.WHITE}Press Ctrl+C to stop honeypot{' ' * 52}{Fore.CYAN}║")
                print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
                
                last_count = connection_count
                
            time.sleep(0.5)
                
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = True
        honeypot_running = False
        print(f"\n{Fore.YELLOW}[*] Honeypot stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def file_watcher():
    """Monitor file system for changes and detect ransomware-like behavior"""
    global file_watcher_running, stop_threads
    
    print(f"{Fore.YELLOW}[*] Setting up file integrity monitor / ransomware detector...")
    
    # Ask for directory to monitor
    default_dir = os.path.expanduser("~")
    watch_dir = input(f"{Fore.YELLOW}[*] Enter directory to monitor (default: {default_dir}): ") or default_dir
    
    if not os.path.exists(watch_dir):
        print(f"{Fore.RED}[!] Directory does not exist")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")
        return
    
    print(f"{Fore.GREEN}[+] Monitoring directory: {watch_dir}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop monitoring\n")
    
    file_watcher_running = True
    stop_threads = False
    
    # Track suspicious file operations
    suspicious_operations = {
        "encrypted": 0,
        "deleted": 0,
        "modified": 0,
        "extensions": set()
    }
    
    # Known ransomware extensions
    ransomware_extensions = {
        ".crypt", ".locked", ".crypto", ".encrypted", ".vvv", ".zzz", ".xxx", 
        ".enc", ".locked", ".crypted", ".cryptor", ".vault", ".petya", ".cerber",
        ".sage", ".locker", ".wncry", ".WNCRY", ".locky", ".osiris", ".OSIRIS", ".WannaCry"
    }
    
    # Store baseline of files and their hashes
    baseline = {}
    
    def calculate_hash(file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            with open(file_path, "rb") as f:
                hash_obj = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
                return hash_obj.hexdigest()
        except Exception:
            return None
            
    def scan_directory(directory):
        """Scan the directory and calculate file hashes"""
        files_info = {}
        
        print(f"{Fore.YELLOW}[*] Creating baseline hashes for: {directory}")
        
        for root, _, files in os.walk(directory):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, directory)
                    
                    # Skip large files and certain directories
                    if os.path.getsize(file_path) > 10000000:  # 10MB limit
                        continue
                        
                    # Skip common system directories
                    if any(skip_dir in rel_path for skip_dir in [".git", "__pycache__", "node_modules"]):
                        continue
                        
                    file_hash = calculate_hash(file_path)
                    if file_hash:
                        files_info[rel_path] = {
                            "hash": file_hash,
                            "size": os.path.getsize(file_path),
                            "last_modified": os.path.getmtime(file_path)
                        }
                except Exception:
                    continue
                    
        return files_info
    
    # Create initial baseline
    print(f"{Fore.YELLOW}[*] Creating initial baseline of files...")
    baseline = scan_directory(watch_dir)
    print(f"{Fore.GREEN}[+] Baseline created with {len(baseline)} files")
    
    # Monitor files
    def monitor_files():
        nonlocal baseline, suspicious_operations
        
        while not stop_threads:
            time.sleep(2)  # Check every 2 seconds
            
            # Compare current state with baseline
            current_files = scan_directory(watch_dir)
            
            # Check for changes
            for file_path, info in baseline.items():
                full_path = os.path.join(watch_dir, file_path)
                
                # Check if file was deleted
                if file_path not in current_files:
                    print(f"{Fore.RED}[!] File deleted: {file_path}")
                    suspicious_operations["deleted"] += 1
                    log_threat("File Integrity", f"File deleted: {file_path}", "Medium")
                    continue
                    
                # Check if file was modified
                if current_files[file_path]["hash"] != info["hash"]:
                    print(f"{Fore.RED}[!] File modified: {file_path}")
                    suspicious_operations["modified"] += 1
                    
                    # Check if the extension changed to a suspicious one
                    _, ext = os.path.splitext(file_path)
                    if ext in ransomware_extensions:
                        print(f"{Fore.RED}[!] RANSOMWARE ALERT: File has suspicious extension: {ext}")
                        suspicious_operations["encrypted"] += 1
                        suspicious_operations["extensions"].add(ext)
                        log_threat("Ransomware", f"File with ransomware extension detected: {file_path}", "Critical")
                    else:
                        log_threat("File Integrity", f"File modified: {file_path}", "Low")
            
            # Check for new files with suspicious extensions
            for file_path in current_files:
                if file_path not in baseline:
                    _, ext = os.path.splitext(file_path)
                    if ext in ransomware_extensions:
                        print(f"{Fore.RED}[!] RANSOMWARE ALERT: New file with suspicious extension: {file_path}")
                        suspicious_operations["encrypted"] += 1
                        suspicious_operations["extensions"].add(ext)
                        log_threat("Ransomware", f"New file with ransomware extension: {file_path}", "Critical")
            
            # Update baseline
            baseline = current_files
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_files)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Display status
    try:
        start_time = datetime.now()
        
        while monitor_thread.is_alive() and not stop_threads:
            current_time = datetime.now()
            uptime = (current_time - start_time).seconds
            
            clear_screen()
            print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"{Fore.CYAN}║ {Fore.YELLOW}FILE INTEGRITY MONITOR & RANSOMWARE DETECTOR{' ' * 37}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Monitoring directory: {watch_dir[:50]}{' ' * (48 - len(watch_dir[:50]))}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Files in baseline: {len(baseline)}{' ' * 57}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Monitor uptime: {uptime} seconds{' ' * 56}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Activity Summary:{' ' * 62}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.RED}Files deleted: {suspicious_operations['deleted']}{' ' * 61}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.YELLOW}Files modified: {suspicious_operations['modified']}{' ' * 59}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.RED}Suspicious encryptions: {suspicious_operations['encrypted']}{' ' * 50}{Fore.CYAN}║")
            
            if suspicious_operations["extensions"]:
                extensions = ", ".join(suspicious_operations["extensions"])
                print(f"{Fore.CYAN}║ {Fore.RED}Suspicious extensions: {extensions[:40]}{' ' * (50 - len(extensions[:40]))}{Fore.CYAN}║")
            else:
                print(f"{Fore.CYAN}║ {Fore.GREEN}No suspicious extensions detected{' ' * 49}{Fore.CYAN}║")
            
            # Threat assessment
            threat_level = "Low"
            if suspicious_operations["encrypted"] > 0:
                threat_level = "CRITICAL"
            elif suspicious_operations["deleted"] > 10:
                threat_level = "High"
            elif suspicious_operations["modified"] > 20:
                threat_level = "Medium"
                
            level_color = (Fore.GREEN if threat_level == "Low" else
                          Fore.YELLOW if threat_level == "Medium" else
                          Fore.RED if threat_level == "High" else
                          Fore.MAGENTA)
                
            print(f"{Fore.CYAN}║ {Fore.WHITE}Current threat level: {level_color}{threat_level}{' ' * (57 - len(threat_level))}{Fore.CYAN}║")
            
            # Recommend actions
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            if threat_level == "CRITICAL":
                print(f"{Fore.CYAN}║ {Fore.MAGENTA}!!! RANSOMWARE ACTIVITY DETECTED !!!{' ' * 45}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.RED}RECOMMENDED ACTION: DISCONNECT FROM NETWORK IMMEDIATELY{' ' * 25}{Fore.CYAN}║")
            elif threat_level == "High":
                print(f"{Fore.CYAN}║ {Fore.RED}High number of file deletions detected{' ' * 45}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.RED}RECOMMENDED ACTION: Investigate file deletions{' ' * 36}{Fore.CYAN}║")
            else:
                print(f"{Fore.CYAN}║ {Fore.GREEN}No immediate threats detected{' ' * 53}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.GREEN}Continuing to monitor file system...{' ' * 47}{Fore.CYAN}║")
                
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Press Ctrl+C to stop monitoring{' ' * 51}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
            
            time.sleep(3)
                
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = True
        file_watcher_running = False
        print(f"\n{Fore.YELLOW}[*] File monitoring stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def hash_checker():
    """Real-time file hash checker for verifying file integrity"""
    global hash_checker_running, stop_threads
    
    hash_checker_running = True
    stop_threads = False
    
    print(f"{Fore.YELLOW}[*] File Hash Integrity Checker")
    
    # Load existing file hashes
    data = load_data()
    
    # Display options
    print(f"{Fore.CYAN}Options:")
    print(f"{Fore.CYAN}1. Check a single file")
    print(f"{Fore.CYAN}2. Scan a directory")
    print(f"{Fore.CYAN}3. Verify against known hashes")
    choice = input(f"{Fore.YELLOW}[*] Enter your choice (1-3): ")
    
    def calculate_file_hash(file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            with open(file_path, "rb") as f:
                bytes_data = f.read()
                return hashlib.sha256(bytes_data).hexdigest()
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}")
            return None
    
    if choice == "1":
        # Single file check
        file_path = input(f"{Fore.YELLOW}[*] Enter path to file: ")
        
        if not os.path.isfile(file_path):
            print(f"{Fore.RED}[!] File not found")
            hash_checker_running = False
            return
            
        print(f"{Fore.YELLOW}[*] Calculating hash for: {os.path.basename(file_path)}")
        start_time = time.time()
        file_hash = calculate_file_hash(file_path)
        end_time = time.time()
        
        if file_hash:
            print(f"{Fore.GREEN}[+] SHA-256: {file_hash}")
            print(f"{Fore.GREEN}[+] Time taken: {end_time - start_time:.2f} seconds")
            
            # Check if we have this hash in our database
            file_name = os.path.basename(file_path)
            if file_name in data["file_hashes"]:
                stored_hash = data["file_hashes"][file_name]
                if stored_hash == file_hash:
                    print(f"{Fore.GREEN}[+] Hash verified! File is unchanged since last check.")
                else:
                    print(f"{Fore.RED}[!] WARNING: Hash mismatch!")
                    print(f"{Fore.RED}[!] Stored hash: {stored_hash}")
                    print(f"{Fore.RED}[!] Current hash: {file_hash}")
                    print(f"{Fore.RED}[!] File may have been modified!")
                    log_threat("File Integrity", f"Hash mismatch for file: {file_name}", "High")
            else:
                # Store the hash for future checks
                save_hash = input(f"{Fore.YELLOW}[*] Store this hash for future verification? (y/n): ")
                if save_hash.lower() == 'y':
                    data["file_hashes"][file_name] = file_hash
                    save_data(data)
                    print(f"{Fore.GREEN}[+] Hash stored for future verification")
                    
    elif choice == "2":
        # Scan directory
        dir_path = input(f"{Fore.YELLOW}[*] Enter directory path: ")
        
        if not os.path.isdir(dir_path):
            print(f"{Fore.RED}[!] Directory not found")
            hash_checker_running = False
            return
            
        print(f"{Fore.YELLOW}[*] Scanning directory: {dir_path}")
        
        hashes = {}
        file_count = 0
        for root, _, files in os.walk(dir_path):
            for file_name in files:
                if stop_threads:
                    break
                    
                file_path = os.path.join(root, file_name)
                try:
                    # Skip large files
                    if os.path.getsize(file_path) > 100000000:  # 100MB
                        continue
                        
                    file_count += 1
                    print(f"\r{Fore.YELLOW}[*] Processed {file_count} files...", end="")
                    file_hash = calculate_file_hash(file_path)
                    if file_hash:
                        rel_path = os.path.relpath(file_path, dir_path)
                        hashes[rel_path] = file_hash
                except Exception:
                    continue
        
        print(f"\r{Fore.GREEN}[+] Processed {file_count} files, generated {len(hashes)} hashes")
        
        # Save option
        save_option = input(f"{Fore.YELLOW}[*] Save these hashes to database? (y/n): ")
        if save_option.lower() == 'y':
            for file_path, file_hash in hashes.items():
                file_name = os.path.basename(file_path)
                data["file_hashes"][file_name] = file_hash
            save_data(data)
            print(f"{Fore.GREEN}[+] Saved {len(hashes)} hashes to database")
            
        # Export option
        export_option = input(f"{Fore.YELLOW}[*] Export hashes to file? (y/n): ")
        if export_option.lower() == 'y':
            export_file = input(f"{Fore.YELLOW}[*] Enter export filename (default: file_hashes.txt): ") or "file_hashes.txt"
            with open(export_file, 'w') as f:
                for file_path, file_hash in hashes.items():
                    f.write(f"{file_hash} *{file_path}\n")
            print(f"{Fore.GREEN}[+] Exported hashes to {export_file}")
            
    elif choice == "3":
        # Verify against known hashes
        if not data["file_hashes"]:
            print(f"{Fore.RED}[!] No stored hashes in database")
            hash_checker_running = False
            return
            
        print(f"{Fore.YELLOW}[*] Available files with stored hashes:")
        for i, (file_name, _) in enumerate(data["file_hashes"].items(), 1):
            print(f"{Fore.CYAN}{i}. {file_name}")
            
        try:
            index = int(input(f"{Fore.YELLOW}[*] Enter file number to verify, or 0 to verify all: "))
            
            if index == 0:
                # Verify all files
                print(f"{Fore.YELLOW}[*] Verifying all files...")
                matched = 0
                mismatched = 0
                missing = 0
                
                for file_name, stored_hash in data["file_hashes"].items():
                    # Look for the file in current directory first
                    if os.path.exists(file_name):
                        file_path = file_name
                    else:
                        # Try to find it by scanning subdirectories
                        found = False
                        for root, _, files in os.walk('.'):
                            if file_name in files:
                                file_path = os.path.join(root, file_name)
                                found = True
                                break
                        if not found:
                            print(f"{Fore.YELLOW}[!] File not found: {file_name}")
                            missing += 1
                            continue
                            
                    current_hash = calculate_file_hash(file_path)
                    if current_hash == stored_hash:
                        print(f"{Fore.GREEN}[+] Verified: {file_name}")
                        matched += 1
                    else:
                        print(f"{Fore.RED}[!] MISMATCH: {file_name}")
                        print(f"{Fore.RED}    Expected: {stored_hash}")
                        print(f"{Fore.RED}    Current:  {current_hash}")
                        mismatched += 1
                        log_threat("File Integrity", f"Hash mismatch for file: {file_name}", "High")
                        
                print(f"\n{Fore.GREEN}[+] Verification complete:")
                print(f"{Fore.GREEN}[+] {matched} files matched")
                print(f"{Fore.RED}[!] {mismatched} files mismatched")
                print(f"{Fore.YELLOW}[!] {missing} files not found")
                
            elif 1 <= index <= len(data["file_hashes"]):
                # Verify single file
                file_name = list(data["file_hashes"].keys())[index-1]
                stored_hash = list(data["file_hashes"].values())[index-1]
                
                # Look for file
                if os.path.exists(file_name):
                    file_path = file_name
                else:
                    # Try to find it
                    file_path = input(f"{Fore.YELLOW}[*] Enter path to {file_name}: ")
                    if not os.path.exists(file_path):
                        print(f"{Fore.RED}[!] File not found")
                        hash_checker_running = False
                        return
                
                print(f"{Fore.YELLOW}[*] Verifying {file_name}...")
                current_hash = calculate_file_hash(file_path)
                
                if current_hash == stored_hash:
                    print(f"{Fore.GREEN}[+] Hash verified! File integrity confirmed.")
                else:
                    print(f"{Fore.RED}[!] WARNING: Hash mismatch!")
                    print(f"{Fore.RED}[!] Stored hash: {stored_hash}")
                    print(f"{Fore.RED}[!] Current hash: {current_hash}")
                    print(f"{Fore.RED}[!] File integrity compromised!")
                    log_threat("File Integrity", f"Hash mismatch for file: {file_name}", "High")
            else:
                print(f"{Fore.RED}[!] Invalid selection")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input")
    else:
        print(f"{Fore.RED}[!] Invalid choice")
    
    hash_checker_running = False
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def firewall_rules():
    """Manage and test zero trust firewall rules"""
    
    def display_rules(rules):
        """Display the firewall rules in a table"""
        print(f"{Fore.CYAN}╔═════╦═══════════════════╦═══════════════════╦═══════════╦════════╗")
        print(f"{Fore.CYAN}║ {Fore.WHITE}ID{Fore.CYAN}  ║ {Fore.WHITE}Source          {Fore.CYAN} ║ {Fore.WHITE}Destination      {Fore.CYAN} ║ {Fore.WHITE}Port      {Fore.CYAN} ║ {Fore.WHITE}Action{Fore.CYAN} ║")
        print(f"{Fore.CYAN}╠═════╬═══════════════════╬═══════════════════╬═══════════╬════════╣")
        
        for i, rule in enumerate(rules, 1):
            action_color = Fore.GREEN if rule["action"] == "ALLOW" else Fore.RED
            print(f"{Fore.CYAN}║ {Fore.WHITE}{i:3d}{Fore.CYAN} ║ "
                  f"{Fore.WHITE}{rule['source'][:17]}{' ' * (17 - len(rule['source'][:17]))}{Fore.CYAN} ║ "
                  f"{Fore.WHITE}{rule['destination'][:17]}{' ' * (17 - len(rule['destination'][:17]))}{Fore.CYAN} ║ "
                  f"{Fore.WHITE}{rule['port'][:9]}{' ' * (9 - len(rule['port'][:9]))}{Fore.CYAN} ║ "
                  f"{action_color}{rule['action']}{' ' * (6 - len(rule['action']))}{Fore.CYAN} ║")
        
        print(f"{Fore.CYAN}╚═════╩═══════════════════╩═══════════════════╩═══════════╩════════╝")
    
    # Load data
    data = load_data()
    
    if "firewall_rules" not in data:
        data["firewall_rules"] = [
            {"source": "ANY", "destination": "192.168.1.1", "port": "22", "action": "DENY"},
            {"source": "192.168.1.0/24", "destination": "ANY", "port": "80,443", "action": "ALLOW"},
            {"source": "10.0.0.5", "destination": "192.168.1.100", "port": "3389", "action": "DENY"},
            {"source": "ANY", "destination": "ANY", "port": "ANY", "action": "DENY"}  # Default deny rule
        ]
        save_data(data)
    
    while True:
        clear_screen()
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}ZERO TRUST FIREWALL CONFIGURATION{' ' * 47}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Display current rules
        display_rules(data["firewall_rules"])
        
        # Options
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.GREEN}1. Add Rule{' ' * 68}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}2. Delete Rule{' ' * 65}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}3. Test Connection{' ' * 61}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}4. Apply Zero Trust Principles{' ' * 50}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}0. Back to Main Menu{' ' * 60}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
        
        choice = input(f"{Fore.YELLOW}[*] Enter your choice (0-4): ")
        
        if choice == "1":
            # Add rule
            print(f"{Fore.YELLOW}[*] Adding new firewall rule...")
            source = input(f"{Fore.YELLOW}[*] Source IP/Network (e.g. 192.168.1.0/24 or 'ANY'): ")
            destination = input(f"{Fore.YELLOW}[*] Destination IP/Host (e.g. 192.168.1.1 or 'ANY'): ")
            port = input(f"{Fore.YELLOW}[*] Port(s) (e.g. 80,443 or 'ANY'): ")
            action = input(f"{Fore.YELLOW}[*] Action (ALLOW/DENY): ").upper()
            
            if action not in ["ALLOW", "DENY"]:
                print(f"{Fore.RED}[!] Invalid action. Use ALLOW or DENY.")
                input(f"{Fore.YELLOW}[*] Press Enter to continue...")
                continue
                
            # Add the rule before the default rule
            new_rule = {"source": source, "destination": destination, "port": port, "action": action}
            if data["firewall_rules"][-1]["source"] == "ANY" and data["firewall_rules"][-1]["destination"] == "ANY":
                data["firewall_rules"].insert(-1, new_rule)
            else:
                data["firewall_rules"].append(new_rule)
                
            save_data(data)
            print(f"{Fore.GREEN}[+] Rule added successfully!")
            
        elif choice == "2":
            # Delete rule
            try:
                rule_id = int(input(f"{Fore.YELLOW}[*] Enter rule ID to delete: "))
                if 1 <= rule_id <= len(data["firewall_rules"]):
                    # Prevent deletion of default deny rule if it's the last one
                    if rule_id == len(data["firewall_rules"]) and data["firewall_rules"][rule_id-1]["source"] == "ANY" and data["firewall_rules"][rule_id-1]["destination"] == "ANY" and data["firewall_rules"][rule_id-1]["action"] == "DENY":
                        print(f"{Fore.RED}[!] Cannot delete default deny rule!")
                    else:
                        deleted_rule = data["firewall_rules"].pop(rule_id-1)
                        save_data(data)
                        print(f"{Fore.GREEN}[+] Rule deleted: {deleted_rule}")
                else:
                    print(f"{Fore.RED}[!] Invalid rule ID")
            except ValueError:
                print(f"{Fore.RED}[!] Invalid input")
                
        elif choice == "3":
            # Test connection
            source_ip = input(f"{Fore.YELLOW}[*] Source IP: ")
            dest_ip = input(f"{Fore.YELLOW}[*] Destination IP: ")
            port = input(f"{Fore.YELLOW}[*] Port: ")
            
            # Evaluate rules
            print(f"{Fore.YELLOW}[*] Testing connection from {source_ip} to {dest_ip}:{port}...")
            print(f"{Fore.YELLOW}[*] Evaluating zero trust firewall rules...")
            
            # Create a progress effect for rule evaluation
            for i in range(5):
                print(f"\r{Fore.YELLOW}[*] Checking rule set{'.' * (i+1)}{' ' * (10 - i)}", end="")
                time.sleep(0.2)
                
            allowed = False
            matched_rule = None
            
            for i, rule in enumerate(data["firewall_rules"], 1):
                # Check if rule matches
                source_match = rule["source"] == "ANY" or source_ip == rule["source"] or (
                    "/" in rule["source"] and is_ip_in_network(source_ip, rule["source"]))
                
                dest_match = rule["destination"] == "ANY" or dest_ip == rule["destination"] or (
                    "/" in rule["destination"] and is_ip_in_network(dest_ip, rule["destination"]))
                
                port_match = rule["port"] == "ANY" or port == rule["port"] or (
                    "," in rule["port"] and port in rule["port"].split(","))
                
                if source_match and dest_match and port_match:
                    matched_rule = rule
                    allowed = rule["action"] == "ALLOW"
                    print(f"\r{Fore.GREEN}[+] Matched rule #{i}: {rule['source']} → {rule['destination']}:{rule['port']} ({rule['action']})")
                    break
            
            print("\n" + "=" * 60)
            if allowed:
                print(f"{Fore.GREEN}[+] CONNECTION ALLOWED: {source_ip} can access {dest_ip} on port {port}")
                print(f"{Fore.GREEN}[+] Zero Trust verification passed")
            else:
                print(f"{Fore.RED}[!] CONNECTION BLOCKED: {source_ip} cannot access {dest_ip} on port {port}")
                if matched_rule:
                    print(f"{Fore.RED}[!] Blocked by rule: {matched_rule['source']} → {matched_rule['destination']}:{matched_rule['port']}")
                else:
                    print(f"{Fore.RED}[!] No matching rule found, default deny applied (Zero Trust)")
            
            # Log the connection attempt
            severity = "Low" if allowed else "Medium"
            details = f"Connection attempt from {source_ip} to {dest_ip}:{port} - {'ALLOWED' if allowed else 'BLOCKED'}"
            log_threat("Firewall", details, severity)
                
        elif choice == "4":
            # Apply Zero Trust principles
            print(f"{Fore.YELLOW}[*] Applying Zero Trust principles to firewall ruleset...")
            time.sleep(1)
            
            # Add proper Zero Trust rules
            zero_trust_rules = [
                {"source": "ANY", "destination": "ANY", "port": "ANY", "action": "DENY"},  # Default deny
                {"source": "10.0.0.0/24", "destination": "10.0.0.5", "port": "443", "action": "ALLOW"},  # Auth server
                {"source": "10.0.0.0/24", "destination": "10.0.0.10", "port": "8443", "action": "ALLOW"},  # MFA service
                {"source": "192.168.1.100", "destination": "10.0.0.20", "port": "3306", "action": "ALLOW"},  # DB access
                {"source": "10.0.0.15", "destination": "192.168.1.0/24", "port": "22", "action": "ALLOW"},  # Admin SSH
            ]
            
            data["firewall_rules"] = zero_trust_rules
            save_data(data)
            
            print(f"{Fore.GREEN}[+] Zero Trust rules applied successfully!")
            print(f"{Fore.GREEN}[+] Implementing principle of least privilege")
            print(f"{Fore.GREEN}[+] Default deny policy activated")
            print(f"{Fore.GREEN}[+] Micro-segmentation rules configured")
            
        elif choice == "0":
            break
            
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def is_ip_in_network(ip, network):
    """Check if an IP is in a network range"""
    try:
        # Simple implementation without requiring external libraries
        if "/" not in network:
            return False
            
        net_ip, mask = network.split("/")
        mask = int(mask)
        
        # Convert IP string to integer
        def ip_to_int(ip_str):
            parts = ip_str.split(".")
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
            
        # Calculate subnet
        ip_int = ip_to_int(ip)
        net_int = ip_to_int(net_ip)
        mask_bits = 0xFFFFFFFF << (32 - mask)
        
        return (ip_int & mask_bits) == (net_int & mask_bits)
    except Exception:
        return False

def dos_attack_simulator():
    """Simulate a DoS attack against a target (purely educational)"""
    print(f"{Fore.YELLOW}[*] DoS Attack Simulator (Educational Purpose Only)")
    print(f"{Fore.RED}[!] WARNING: This is a simulation only. DO NOT use against real targets without permission!")
    
    # Get target details
    target_phone = input(f"{Fore.YELLOW}[*] Enter target phone number (for simulation): ")
    
    # Validate phone number format (simple check)
    if not re.match(r'^\+?[\d\-\(\) ]{10,15}$', target_phone):
        print(f"{Fore.RED}[!] Invalid phone number format. Using placeholder.")
        target_phone = "+1-XXX-XXX-XXXX"
    
    try:
        num_messages = int(input(f"{Fore.YELLOW}[*] Number of messages to simulate sending (10-100): "))
        num_messages = max(10, min(100, num_messages))  # Limit between 10-100
    except ValueError:
        num_messages = 25
        print(f"{Fore.RED}[!] Invalid input. Using default of 25 messages.")
    
    # Message templates
    message_templates = [
        "URGENT: Your account has been locked. Verify now at http://sc4m-{}.com",
        "You've won $1000 gift card! Claim at http://free-pr1ze-{}.net",
        "Security alert: Unusual login detected. Confirm identity: http://secure-{}.com",
        "30% OFF your next purchase! Limited time offer: http://sh0p-d1sc0unt-{}.biz",
        "Payment declined. Update payment info: http://b1ll-p4y-{}.info",
        "Package delivery attempted. Schedule redelivery: http://tr4ck-{}.co",
        "Final notice: Your subscription will be canceled. Renew: http://sub-renew-{}.net",
        "Bank alert: Transfer of $750 processing. Cancel: http://bank-verify-{}.com"
    ]
    
    print(f"\n{Fore.YELLOW}[*] Initiating simulated DoS SMS attack against {target_phone}")
    print(f"{Fore.YELLOW}[*] Targeting with {num_messages} spam messages")
    print(f"{Fore.YELLOW}[*] Connecting to simulated SMS gateway...")
    
    # Create progress bar
    time.sleep(1.5)
    
    # Show connection simulation
    for i in range(5):
        print(f"\r{Fore.YELLOW}[*] Establishing connection{' .' * i}", end="")
        time.sleep(0.3)
    
    print(f"\r{Fore.GREEN}[+] Connection established to SMS relay             ")
    time.sleep(0.5)
    
    # Start the attack simulation
    print(f"\n{Fore.YELLOW}[*] Starting DoS SMS flood (simulation):")
    
    success_count = 0
    fail_count = 0
    
    for i in range(num_messages):
        # Generate random message from templates
        random_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))
        message = random.choice(message_templates).format(random_id)
        
        # Randomize success/failure (mostly success for effect)
        success = random.random() < 0.9
        status = f"{Fore.GREEN}SUCCESS" if success else f"{Fore.RED}FAILED"
        
        if success:
            success_count += 1
        else:
            fail_count += 1
        
        # Display message sending
        print(f"{Fore.CYAN}[{i+1}/{num_messages}] {status} → {target_phone}: {message[:40]}...")
        
        # Random delay between messages
        time.sleep(random.uniform(0.1, 0.3))
    
    # Attack summary
    print(f"\n{Fore.YELLOW}[*] DoS SMS attack simulation completed")
    print(f"{Fore.GREEN}[+] Messages sent successfully: {success_count}")
    print(f"{Fore.RED}[+] Messages failed: {fail_count}")
    print(f"{Fore.YELLOW}[*] Target may experience temporary service disruption (simulated)")
    
    # Log the activity
    log_threat("DoS Attack", f"Simulated SMS flood against {target_phone}", "High")
    
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def log_visualizer():
    """Real-Time Log Visualization in Terminal with fancy TUI"""
    global stop_threads
    stop_threads = False
    
    # Load existing logs
    data = load_data()
    logs = data["threat_logs"]
    
    if not logs:
        print(f"{Fore.YELLOW}[*] No logs available for visualization.")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")
        return
    
    # Prepare log data for visualization
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    type_counts = {}
    time_series = {}
    
    # Function to process logs
    def process_logs(logs):
        nonlocal severity_counts, type_counts, time_series
        
        # Reset counters
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        type_counts = {}
        time_series = {}
        
        # Process each log entry
        for log in logs:
            # Count by severity
            severity = log.get("severity", "Low")
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Count by type
            log_type = log.get("type", "Unknown")
            if log_type not in type_counts:
                type_counts[log_type] = 0
            type_counts[log_type] += 1
            
            # Time series data (by hour)
            try:
                # Extract hour from timestamp
                timestamp = log.get("timestamp", "00:00:00")
                if len(timestamp) >= 8:  # Make sure it has HH:MM:SS format
                    hour = timestamp[:2]
                    if hour not in time_series:
                        time_series[hour] = 0
                    time_series[hour] += 1
            except Exception:
                pass
    
    # Process initial logs
    process_logs(logs)
    
    def draw_visualization():
        """Draw the log visualization dashboard"""
        clear_screen()
        
        # Header
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}REAL-TIME LOG VISUALIZATION & ANALYTICS{' ' * 40}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Severity distribution chart
        print(f"{Fore.CYAN}║ {Fore.WHITE}Threat Severity Distribution:{' ' * 51}{Fore.CYAN}║")
        
        max_count = max(severity_counts.values()) if severity_counts.values() else 1
        for severity, count in severity_counts.items():
            # Calculate bar length (max 40 chars)
            bar_length = int((count / max_count) * 40) if max_count > 0 else 0
            bar = "█" * bar_length
            
            # Choose color by severity
            color = (Fore.MAGENTA if severity == "Critical" else
                    Fore.RED if severity == "High" else
                    Fore.YELLOW if severity == "Medium" else
                    Fore.GREEN)
            
            print(f"{Fore.CYAN}║ {color}{severity:8}: {count:3d} {bar}{' ' * (41 - bar_length)}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Threat type distribution (top 5)
        print(f"{Fore.CYAN}║ {Fore.WHITE}Top Threat Types:{' ' * 63}{Fore.CYAN}║")
         
        # Sort by count (descending)
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        max_type_count = max([count for _, count in sorted_types]) if sorted_types else 1
        for threat_type, count in sorted_types:
            # Calculate bar length (max 30 chars)
            bar_length = int((count / max_type_count) * 30) if max_type_count > 0 else 0
            bar = "█" * bar_length
            
            # Truncate long type names
            disp_type = threat_type[:15] + "..." if len(threat_type) > 18 else threat_type
            disp_type = disp_type.ljust(18)
            
            print(f"{Fore.CYAN}║ {Fore.BLUE}{disp_type}: {count:3d} {Fore.GREEN}{bar}{' ' * (30 - bar_length)}{Fore.CYAN}║")
        
        # Fill empty lines if less than 5 types
        for _ in range(5 - len(sorted_types)):
            print(f"{Fore.CYAN}║{' ' * 78}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Time series chart
        print(f"{Fore.CYAN}║ {Fore.WHITE}Alert Activity by Hour:{' ' * 57}{Fore.CYAN}║")
        
        # Sort hours numerically
        sorted_hours = sorted(time_series.items(), key=lambda x: int(x[0]))
        
        # Create time series chart
        if sorted_hours:
            max_hour_count = max([count for _, count in sorted_hours])
            
            # Print chart
            for hour, count in sorted_hours:
                # Calculate bar length (max 30 chars)
                bar_length = int((count / max_hour_count) * 30) if max_hour_count > 0 else 0
                bar = "█" * bar_length
                
                print(f"{Fore.CYAN}║ {Fore.YELLOW}{hour}:00 - {int(hour)+1:02d}:00: {count:3d} {Fore.CYAN}{bar}{' ' * (30 - bar_length)}{Fore.CYAN}║")
        else:
            print(f"{Fore.CYAN}║ {Fore.YELLOW}No time series data available{' ' * 50}{Fore.CYAN}║")
            
        # Fill empty lines for consistent display
        for _ in range(4 - len(sorted_hours)):
            print(f"{Fore.CYAN}║{' ' * 78}{Fore.CYAN}║")
            
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Latest alerts
        print(f"{Fore.CYAN}║ {Fore.WHITE}Latest Security Alerts:{' ' * 56}{Fore.CYAN}║")
        
        # Show the 5 most recent logs
        recent_logs = logs[-5:] if len(logs) >= 5 else logs
        for log in reversed(recent_logs):
            timestamp = log.get("timestamp", "00:00:00")
            log_type = log.get("type", "Unknown")
            details = log.get("details", "No details")
            severity = log.get("severity", "Low")
            
            # Truncate long details
            if len(details) > 40:
                details = details[:37] + "..."
                
            # Color by severity
            sev_color = (Fore.MAGENTA if severity == "Critical" else
                        Fore.RED if severity == "High" else
                        Fore.YELLOW if severity == "Medium" else
                        Fore.GREEN)
                
            print(f"{Fore.CYAN}║ {sev_color}[{severity[0]}] {timestamp} | {log_type[:10]}: {details}{' ' * (40 - len(details))}{Fore.CYAN}║")
            
        # Fill empty lines if less than 5 logs
        for _ in range(5 - len(recent_logs)):
            print(f"{Fore.CYAN}║{' ' * 78}{Fore.CYAN}║")
            
        # Footer
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Auto-refresh enabled. Press Ctrl+C to exit.{' ' * 38}{Fore.CYAN} ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
    
    # Main visualization loop
    try:
        while not stop_threads:
            # Reload data to get fresh logs
            data = load_data()
            logs = data["threat_logs"]
            
            # Process logs and draw visualization
            process_logs(logs)
            draw_visualization()
            
            # Wait before refresh
            time.sleep(2)
            
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Log visualization stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def insider_threat_tracker():
    """Track potential insider threats like file copying, clipboard activity"""
    global stop_threads
    stop_threads = False
    
    print(f"{Fore.YELLOW}[*] Starting Insider Threat Tracker...")
    print(f"{Fore.YELLOW}[*] Monitoring system for suspicious activities...")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop monitoring\n")
    
    # Create monitored directories
    monitored_dirs = [os.path.join(os.path.expanduser("~"), "Documents")]
    sensitive_extensions = ['.docx', '.xlsx', '.pdf', '.txt', '.csv', '.key', '.pem', '.conf']
    
    # Initial scan of directories
    baseline_files = {}
    for directory in monitored_dirs:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        baseline_files[file_path] = {
                            "size": os.path.getsize(file_path),
                            "modified": os.path.getmtime(file_path)
                        }
                    except:
                        pass
    
    print(f"{Fore.GREEN}[+] Baseline created with {len(baseline_files)} files")
    
    # Initialize counters
    activities = {
        "file_copies": 0,
        "clipboard_events": 0,
        "suspicious_processes": 0,
        "large_file_transfers": 0,
        "after_hours_activity": 0
    }
    
    # Store alerts
    alerts = []
    
    def is_after_hours():
        """Check if current time is after business hours (6pm - 8am)"""
        hour = datetime.now().hour
        return hour < 8 or hour >= 18
    
    def check_clipboard():
        """Monitor clipboard for sensitive content"""
        try:
            # Simulate clipboard detection
            if random.random() < 0.1:  # 10% chance of "detecting" clipboard content
                activities["clipboard_events"] += 1
                
                # Generate simulated clipboard content
                patterns = [
                    "password:",
                    "username:",
                    "api_key",
                    "secret",
                    "confidential",
                    "credit card",
                    "ssn",
                    "database password"
                ]
                
                detected_pattern = random.choice(patterns)
                alert = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "type": "Clipboard",
                    "details": f"Sensitive pattern detected: '{detected_pattern}'"
                }
                
                alerts.append(alert)
                log_threat("Insider Threat", f"Clipboard contains sensitive pattern: {detected_pattern}", "Medium")
                return True
        except:
            pass
        return False
    
    def check_processes():
        """Monitor for suspicious processes"""
        try:
            suspicious_proc_names = [
                "scp", "ftp", "dropbox", "megasync", "winzip", 
                "7z", "winscp", "parsec", "teamviewer", "anydesk"
            ]
            
            # Get running processes
            if random.random() < 0.15:  # 15% chance of "detecting" suspicious process
                proc_name = random.choice(suspicious_proc_names)
                activities["suspicious_processes"] += 1
                
                alert = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "type": "Process",
                    "details": f"Suspicious process detected: {proc_name}"
                }
                
                alerts.append(alert)
                severity = "High" if is_after_hours() else "Medium"
                log_threat("Insider Threat", f"Suspicious process running: {proc_name}", severity)
                return True
        except:
            pass
        return False
    
    def check_file_changes():
        """Monitor for file changes, especially large copies"""
        try:
            current_files = {}
            for directory in monitored_dirs:
                if os.path.exists(directory):
                    for root, _, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                current_files[file_path] = {
                                    "size": os.path.getsize(file_path),
                                    "modified": os.path.getmtime(file_path)
                                }
                            except:
                                pass

                            # Check for new files or modified files
                            if file_path not in baseline_files:
                                # New file detected
                                _, ext = os.path.splitext(file_path)
                                if ext.lower() in sensitive_extensions:
                                    activities["file_copies"] += 1
                                    alert = {
                                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                                        "type": "File Copy",
                                        "details": f"New sensitive file detected: {os.path.basename(file_path)}"
                                    }
                                    
                                    alerts.append(alert)
                                    
                                    # Check file size
                                    file_size_mb = current_files[file_path]["size"] / (1024 * 1024)
                                    if file_size_mb > 1:  # Files larger than 1MB
                                        activities["large_file_transfers"] += 1
                                        
                                        severity = "High" if is_after_hours() else "Medium"
                                        log_threat("Data Exfiltration", 
                                                  f"Large file created: {os.path.basename(file_path)} ({file_size_mb:.2f} MB)", 
                                                  severity)
                                            
                                elif (baseline_files[file_path]["modified"] != current_files[file_path]["modified"] or
                                      baseline_files[file_path]["size"] != current_files[file_path]["size"]):
                                    # File was modified
                                    activities["file_copies"] += 1
                                    
                                    alert = {
                                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                                        "type": "File Modified",
                                        "details": f"File modified: {os.path.basename(file_path)}"
                                    }
                                    
                                    alerts.append(alert)
                                    
                              
            
            # Update baseline
            baseline_files = current_files
            
            # Check for after-hours activity
            if is_after_hours() and (activities["file_copies"] > 0 or activities["clipboard_events"] > 0):
                activities["after_hours_activity"] += 1
                
                alert = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "type": "After Hours",
                    "details": f"Unusual activity detected outside business hours"
                }
                
                alerts.append(alert)
                log_threat("Insider Threat", "After-hours file or clipboard activity", "High")
                
            return activities["file_copies"] > 0
        except:
            return False
    
    # Main monitoring loop
    try:
        last_draw_time = 0
        
        while not stop_threads:
            # Check for various threat indicators
            file_activity = check_file_changes()
            clipboard_activity = check_clipboard()
            process_activity = check_processes()
            
            # Draw interface every second
            current_time = time.time()
            if current_time - last_draw_time >= 1:
                clear_screen()
                
                # Display dashboard
                print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}INSIDER THREAT DETECTION SYSTEM{' ' * 49}{Fore.CYAN}            ║")
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                
                # Status overview
                monitoring_status = f"{Fore.GREEN}ACTIVE" if not stop_threads else f"{Fore.RED}STOPPED"
                print(f"{Fore.CYAN}║ {Fore.WHITE}Monitoring Status: {monitoring_status}{' ' * (59 - len('ACTIVE'))}{Fore.CYAN}║")
                
                # Calculate threat level
                threat_level = "Low"
                if activities["file_copies"] > 5 or activities["after_hours_activity"] > 0:
                    threat_level = "High"
                elif activities["clipboard_events"] > 3 or activities["suspicious_processes"] > 2:
                    threat_level = "Medium"
                    
                level_color = (Fore.GREEN if threat_level == "Low" else
                              Fore.YELLOW if threat_level == "Medium" else
                              Fore.RED)
                              
                print(f"{Fore.CYAN}║ {Fore.WHITE}Current Threat Level: {level_color}{threat_level}{' ' * (55 - len(threat_level))}{Fore.CYAN}║")
                
                # Activity counters
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                print(f"{Fore.CYAN}║ {Fore.WHITE}Activity Summary:{' ' * 62}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}File Copies/Modifications: {activities['file_copies']}{' ' * (49 - len(str(activities['file_copies'])))}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}Clipboard Events: {activities['clipboard_events']}{' ' * (57 - len(str(activities['clipboard_events'])))}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}Suspicious Processes: {activities['suspicious_processes']}{' ' * (55 - len(str(activities['suspicious_processes'])))}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}Large File Transfers: {activities['large_file_transfers']}{' ' * (55 - len(str(activities['large_file_transfers'])))}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.YELLOW}After-Hours Activity: {activities['after_hours_activity']}{' ' * (56 - len(str(activities['after_hours_activity'])))}{Fore.CYAN}║")
                
                # Latest alerts
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                print(f"{Fore.CYAN}║ {Fore.WHITE}Latest Alerts:{' ' * 65}{Fore.CYAN}║")
                
                # Show the 5 most recent alerts
                recent_alerts = alerts[-5:] if len(alerts) >= 5 else alerts
                for alert in reversed(recent_alerts):
                    timestamp = alert.get("timestamp", "00:00:00")
                    alert_type = alert.get("type", "Unknown")
                    details = alert.get("details", "No details")
                    
                    # Truncate long details
                    if len(details) > 50:
                        details = details[:47] + "..."
                        
                    # Color by type
                    type_color = (Fore.RED if alert_type == "After Hours" else
                                 Fore.MAGENTA if alert_type == "File Copy" else
                                 Fore.YELLOW if alert_type == "Clipboard" else
                                 Fore.CYAN)
                    
                    print(f"{Fore.CYAN}║ {type_color}[{timestamp}] {alert_type}: {details}{' ' * (45 - len(details))}{Fore.CYAN}║")
                
                # Fill empty lines if less than 5 alerts
                for _ in range(5 - len(recent_alerts)):
                    print(f"{Fore.CYAN}║{' ' * 78}{Fore.CYAN}║")
                
                # Footer
                print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
                print(f"{Fore.CYAN}║ {Fore.WHITE}Monitoring directories: {monitored_dirs[0]}{' ' * (58 - len(monitored_dirs[0][:30]))}{Fore.CYAN}║")
                print(f"{Fore.CYAN}║ {Fore.WHITE}Press Ctrl+C to stop monitoring{' ' * 51}{Fore.CYAN}║")
                print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
                
                last_draw_time = current_time
            
            # Sleep between checks
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Insider threat tracking stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def hash_reverser():
    """Simple hash reverser for demonstration purposes"""
    print(f"{Fore.YELLOW}[*] Hash Reverser Tool")
    print(f"{Fore.YELLOW}[*] This tool can reverse weak hashes for educational purposes")
    
    hash_value = input(f"{Fore.YELLOW}[*] Enter the hash to reverse: ")
    
    # Validate input is a hash
    if not re.match(r'^[a-fA-F0-9]+$', hash_value):
        print(f"{Fore.RED}[!] Invalid hash format. Must contain only hex digits.")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")
        return
    
    # Determine hash type
    hash_type = "Unknown"
    hash_length = len(hash_value)
    
    if hash_length == 32:
        hash_type = "MD5"
    elif hash_length == 40:
        hash_type = "SHA-1"
    elif hash_length == 64:
        hash_type = "SHA-256"
    elif hash_length == 128:
        hash_type = "SHA-512"
    
    print(f"{Fore.GREEN}[+] Detected hash type: {hash_type}")
    print(f"{Fore.YELLOW}[*] Searching for hash in rainbow tables...")
    
    # Simulate hash cracking with rainbow tables
    print(f"{Fore.YELLOW}[*] Initiating rainbow table lookup...")
    
    # Progress bar simulation
    for i in range(10):
        print(f"\r{Fore.YELLOW}[*] Searching through rainbow tables... {i*10}%", end="")
        time.sleep(0.3)
    
    print(f"\r{Fore.GREEN}[+] Search complete!{' ' * 30}")
    
    # For demonstration, we'll use a dictionary of common passwords and their hashes
    # In a real system, you would use rainbow tables or other lookup methods
    common_passwords = {
        "password": "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5
        "123456": "e10adc3949ba59abbe56e057f20f883e",    # MD5
        "admin": "21232f297a57a5a743894a0e4a801fc3",     # MD5
        "letmein": "0d107d09f5bbe40cade3de5c71e9e9b7",   # MD5
        "monkey": "d0763edaa9d9bd2a9516280e9044d885",    # MD5
        "sunshine": "8d2f1650ce1d592c398a95f99dfe8782",  # MD5
        "qwerty": "d8578edf8458ce06fbc5bb76a58c5ca4",    # MD5
        "111111": "96e79218965eb72c92a549dd5a330112",    # MD5
        "abc123": "e99a18c428cb38d5f260853678922e03",    # MD5
    }
    
    # Generate SHA-1 hashes for the same passwords
    sha1_passwords = {
        password: hashlib.sha1(password.encode()).hexdigest() 
        for password in common_passwords.keys()
    }
    
    # Generate SHA-256 hashes for the same passwords
    sha256_passwords = {
        password: hashlib.sha256(password.encode()).hexdigest() 
        for password in common_passwords.keys()
    }
    
    # Check if the hash is in our "database"
    found = False
    
    # For MD5
    if hash_type == "MD5":
        for password, hashed in common_passwords.items():
            if hash_value.lower() == hashed:
                print(f"{Fore.GREEN}[+] Hash successfully reversed!")
                print(f"{Fore.GREEN}[+] Original value: {password}")
                found = True
                break
    
    # For SHA-1
    elif hash_type == "SHA-1":
        for password, hashed in sha1_passwords.items():
            if hash_value.lower() == hashed:
                print(f"{Fore.GREEN}[+] Hash successfully reversed!")
                print(f"{Fore.GREEN}[+] Original value: {password}")
                found = True
                break
    
    # For SHA-256
    elif hash_type == "SHA-256":
        for password, hashed in sha256_passwords.items():
            if hash_value.lower() == hashed:
                print(f"{Fore.GREEN}[+] Hash successfully reversed!")
                print(f"{Fore.GREEN}[+] Original value: {password}")
                found = True
                break
    
    if not found:
        # Display educational message about hash reversing
        print(f"{Fore.RED}[!] Hash could not be reversed using our limited database")
        print(f"{Fore.YELLOW}[*] In real-world scenarios, stronger hashes (SHA-256+) with proper salting")
        print(f"{Fore.YELLOW}[*] cannot be easily reversed, especially with unique passwords.")
        
        # Suggest brute force approach
        print(f"{Fore.YELLOW}[*] Would you like to attempt a brute force attack? (will be simulated)")
        choice = input(f"{Fore.YELLOW}[*] Attempt brute force? (y/n): ")
        
        if choice.lower() == 'y':
            print(f"{Fore.YELLOW}[*] Initiating simulated brute force attack...")
            print(f"{Fore.YELLOW}[*] Testing common password patterns...")
            
            # Simulate brute force progress
            for i in range(20):
                if i < 18:  # Fail for the first 18 iterations
                    if i % 3 == 0:
                        pattern = "Testing numeric sequences..."
                    elif i % 3 == 1:
                        pattern = "Testing dictionary words..."
                    else:
                        pattern = "Testing name combinations..."
                        
                    print(f"\r{Fore.YELLOW}[*] {pattern} {i*5}%", end="")
                    time.sleep(0.2)
                else:
                    # "Succeed" at the end
                    print(f"\r{Fore.GREEN}[+] Password pattern found! 90%{' ' * 10}")
                    time.sleep(0.5)
                    print(f"\r{Fore.GREEN}[+] Cracking final hash... 100%{' ' * 10}")
                    time.sleep(0.5)
                    
                    # Generate a plausible password based on the hash type
                    if hash_type == "MD5":
                        cracked = "P@ssw0rd123!"
                    elif hash_type == "SHA-1":
                        cracked = "Secur3P@ssword!"
                    else:
                        cracked = "StrongP@ssw0rd2023!"
                        
                    print(f"{Fore.GREEN}[+] Hash cracked successfully!")
                    print(f"{Fore.GREEN}[+] Original value: {cracked}")
                    
                    # Log the successful crack
                    log_threat("Hash Cracking", f"Successfully reversed {hash_type} hash", "Medium")
                    break
    else:
        # Log the successful reverse
        log_threat("Hash Cracking", f"Successfully reversed {hash_type} hash using rainbow tables", "Medium")
    
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def generate_report():
    """Generate or download a cybersecurity report"""
    # Here you can implement the logic to generate the report, 
    # e.g., gather data, format it, and save it to a file (e.g., PDF or TXT).
    report_content = """
    Cybersecurity Toolkit Report
    ============================

    1. MFA Brute Force Simulator: [Status]
    2. Port Scanner: [Status]
    3. Real-time Packet Sniffer: [Status]
    4. MAC Address Spoof Detector: [Status]
    5. SOC Security Dashboard: [Status]
    6. Firewall Configuration: [Status]
    7. File Integrity Monitor: [Status]
    8. Honeypot Deployer: [Status]
    9. Threat Intelligence Feeds: [Status]
    10. Log Analysis & Visualization: [Status]
    11. Device Trust Assessment: [Status]
    12. Insider Threat Tracker: [Status]
    13. Hash Reverser: [Status]

    [Report Summary and Conclusions...]
    """
    with open("cybersecurity_report.txt", "w") as report_file:
        report_file.write(report_content)
    
    print(f"{Fore.GREEN}[*] Report generated successfully: cybersecurity_report.txt")

def main():
    """Display the main menu of the cybersecurity toolkit"""
    global current_user, stop_threads

    while True:
        print_banner()

        # Only show relevant tools based on role
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}ZERO TRUST CYBERSECURITY TOOLKIT MENU{' ' * 42}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.GREEN}1. MFA Brute Force Simulator      {Fore.CYAN}║ {Fore.GREEN}2. Port Scanner{' ' * 27}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}3. Real-time Packet Sniffer       {Fore.CYAN}║ {Fore.GREEN}4. MAC Address Spoof Detector{' ' * 15}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}5. SOC Security Dashboard         {Fore.CYAN}║ {Fore.GREEN}6. Firewall Configuration{' ' * 18}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}7. File Integrity Monitor         {Fore.CYAN}║ {Fore.GREEN}8. Honeypot Deployer{' ' * 23}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}9. Threat Intelligence Feeds      {Fore.CYAN}║ {Fore.GREEN}10. Log Analysis & Visualization{' ' * 12}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}11. Device Trust Assessment      {Fore.CYAN} ║ {Fore.GREEN}12. Insider Threat Tracker{' ' * 18}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}13. Hash Reverser                {Fore.CYAN} ║ {Fore.GREEN}14. Generate/Download Report{' ' * 10}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║                                {Fore.RED}0. Exit{' ' * 71}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")

        choice = input(f"\n{Fore.GREEN}[+] Enter your choice (0-14): ")

        if choice == '0':
            print(f"\n{Fore.YELLOW}[*] Shutting down Zero Trust Cybersecurity Toolkit...")
            stop_threads = True
            time.sleep(1)
            clear_screen()
            sys.exit(0)
        elif choice == '1':
            mfa_bruteforce()
        elif choice == '2':
            target = input(f"{Fore.GREEN}[+] Enter target IP address: ")
            scan_ports(target)
        elif choice == '3':
            packet_sniffer()
        elif choice == '4':
            mac_spoof_detector()
        elif choice == '5':
            try:
                print(f"{Fore.YELLOW}[*] Press Ctrl+C to exit the dashboard")
                soc_dashboard()
            except KeyboardInterrupt:
                pass
        elif choice == '6':
            firewall_rules()
        elif choice == '7':
            file_watcher()
        elif choice == '8':
            honeypot()
        elif choice == '9':
            dos_attack_simulator()
        elif choice == '10':
            log_visualizer()
        elif choice == '11':
            file_watcher()
        elif choice == '12':
            insider_threat_tracker()
        elif choice == '13':
            hash_reverser()
        elif choice == '14':
            generate_report()  # Option to generate/download report
        else:
            print(f"\n{Fore.RED}[!] Invalid choice or feature not yet implemented")
            input(f"{Fore.YELLOW}[*] Press Enter to continue...")

if __name__ == '__main__':
    main()

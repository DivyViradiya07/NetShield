import subprocess
import os
import sys
import ctypes
import socket
from datetime import datetime
import psutil
import re
import platform
import threading
import queue
import time
import json # Import json for saving/loading whitelist

# Define paths for storing results
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results", "network_scanner")
WHITELIST_FILE = os.path.join(RESULTS_DIR, "whitelisted_ports.json")
SCAN_RESULT_TCP = os.path.join(RESULTS_DIR, "scan_result_tcp.txt")
SCAN_RESULT_UDP = os.path.join(RESULTS_DIR, "scan_result_udp.txt")
SCAN_RESULT_OS = os.path.join(RESULTS_DIR, "scan_result_os.txt")
SCAN_RESULT_FRAGMENTED = os.path.join(RESULTS_DIR, "scan_result_fragmented.txt")
SCAN_RESULT_AGGRESSIVE = os.path.join(RESULTS_DIR, "scan_result_aggressive.txt")
SCAN_RESULT_TCP_SYN = os.path.join(RESULTS_DIR, "scan_result_tcp_syn.txt")

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# Global queue for logging messages to be consumed by Flask
log_queue = queue.Queue()

# Globals for application state
open_ports = {"TCP": [], "UDP": []}
whitelisted_ports = set()

def log(message):
    """
    Logs messages to an in-memory queue and to a file.
    This log function is designed to be consumed by the Flask app.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n" # SSE format
    
    # Put message into the queue for Flask to stream
    log_queue.put(full_message)

    # Also write to a file for persistent logging
    try:
        log_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "network_agent_log.txt")
        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        # Log to console if file write fails, as this is a critical logging function
        print(f"ERROR: Failed to write to {log_file_path}: {e}")

def send_sse_event(event_name, data=""):
    """Sends a custom SSE event to the frontend."""
    # Ensure data is a JSON string if it's an object/list
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data) # Convert other types to string

    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    log_queue.put(sse_message)

# --- Whitelist Persistence Functions ---
def load_whitelist():
    """Loads whitelisted ports from a JSON file."""
    global whitelisted_ports
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                loaded_ports = json.load(f)
                if isinstance(loaded_ports, list):
                    whitelisted_ports = set(loaded_ports)
                    log(f"[+] Loaded {len(whitelisted_ports)} whitelisted ports from {WHITELIST_FILE}.")
                else:
                    log(f"[!] Whitelist file '{WHITELIST_FILE}' contains invalid format. Starting with empty whitelist.")
                    whitelisted_ports = set()
        except json.JSONDecodeError as e:
            log(f"[!] Error decoding whitelist file '{WHITELIST_FILE}': {e}. Starting with empty whitelist.")
            whitelisted_ports = set()
        except Exception as e:
            log(f"[!] Unexpected error loading whitelist file '{WHITELIST_FILE}': {e}. Starting with empty whitelist.")
            whitelisted_ports = set()
    else:
        log(f"[*] Whitelist file '{WHITELIST_FILE}' not found. Starting with empty whitelist.")
    save_whitelist() # Ensure file exists and is valid on startup

def save_whitelist():
    """Saves the current whitelisted ports to a JSON file."""
    try:
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(list(whitelisted_ports), f, indent=4)
        log(f"[+] Whitelist saved to {WHITELIST_FILE}.")
    except Exception as e:
        log(f"[!] Error saving whitelist to file '{WHITELIST_FILE}': {e}")

def clear_whitelist():
    """Clears the whitelisted ports and saves the empty state."""
    global whitelisted_ports
    whitelisted_ports.clear()
    save_whitelist()
    log("[*] Whitelist cleared.")

# --- OS-Specific Helper Functions ---

def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0 # Default for Linux/macOS

# Elevation
def is_admin():
    """Checks if the script is running with administrative/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception as e:
            log(f"[!] Error checking admin privileges (Windows): {e}")
            return False
    else: # Linux/macOS
        return os.geteuid() == 0

def elevate_if_needed():
    """
    Elevates the script to administrator/root privileges if not already running as such.
    For a Flask app, this would typically be handled by the user running the Flask server
    with elevated privileges, or by a service wrapper. This function serves as a reminder
    of the privilege requirement.
    """
    if not is_admin():
        msg = "This application requires administrative/root privileges to function correctly (e.g., for port blocking and detailed process info). Please run the Flask server with appropriate privileges."
        log(f"[!] Privilege Required: {msg}")
        # In a web app, we can't exit the process like in Tkinter, but we should inform.
        return False
    return True

# Network Helpers
def get_local_ip():
    """Detects and returns the local IP address."""
    interfaces = psutil.net_if_addrs()
    for iface, addrs in interfaces.items():
        if platform.system() == "Windows":
            # Skip common virtual/loopback interfaces on Windows
            if any(x in iface for x in ["Virtual", "VMware", "Loopback", "vEthernet", "WSL"]):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address.startswith("192.168."):
                    return addr.address
        else: # Linux/macOS
            # Skip common virtual/loopback interfaces on Linux/macOS
            if any(x in iface for x in ["lo", "docker", "virbr", "veth", "br-"]):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if ip.startswith("192.168.") or ip.startswith("10.") or \
                       (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31):
                        return ip
    return "127.0.0.1" # Fallback

def is_valid_ip_or_range(target):
    """
    Validates if the input is a valid IP address, CIDR range, or IP range.
    Basic validation for common formats.
    """
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    cidr_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])$"
    ip_range_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}-(?:[0-9]{1,3})$"

    if re.match(ip_regex, target):
        octets = target.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif re.match(cidr_regex, target):
        ip_part, cidr_part = target.split('/')
        octets = ip_part.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif re.match(ip_range_regex, target):
        parts = target.split('-')
        first_ip_octets = parts[0].split('.')
        if all(0 <= int(octet) <= 255 for octet in first_ip_octets) and 0 <= int(parts[1]) <= 255:
            return True
    
    return False

def is_docker_available():
    """Checks if Docker is installed and accessible on the system."""
    try:
        subprocess.check_output(['docker', 'info'], text=True, stderr=subprocess.PIPE, creationflags=_get_subprocess_creation_flags())
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Docker daemon not running or not accessible: {e.stderr.strip() if e.stderr else 'No stderr output'}")
        return False
    except FileNotFoundError:
        log("[!] Docker command not found. Please ensure Docker Desktop/Engine is installed and in your PATH.")
        return False
    except Exception as e:
        log(f"[!] An unexpected error occurred while checking Docker: {e}")
        return False

def ensure_nmap_docker_image():
    """
    Checks if the uzyexe/nmap Docker image is present. If not, attempts to pull it.
    Returns True if the image is available (or successfully pulled), False otherwise.
    """
    image_name = "uzyexe/nmap"
    log(f"[*] Checking for Docker image: {image_name}...")
    try:
        result = subprocess.run(['docker', 'images', '-q', image_name], capture_output=True, text=True, check=False, creationflags=_get_subprocess_creation_flags())
        if result.stdout.strip():
            log(f"[✓] Docker image {image_name} is already present locally.")
            return True
        else:
            log(f"[*] Docker image {image_name} not found locally. Attempting to pull...")
            pull_result = subprocess.run(['docker', 'pull', image_name], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
            log(f"[+] Successfully pulled Docker image: {image_name}")
            return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to pull Docker image {image_name}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False
    except FileNotFoundError:
        log("[!] Docker command not found. Cannot check or pull Docker image.")
        return False
    except Exception as e:
        log(f"[!] An unexpected error occurred during Docker image management: {e}")
        return False

def get_process_info_for_port(port_num, protocol="TCP"):
    """
    Attempts to find the process name listening on a specific TCP/UDP port.
    Returns the process name or "N/A" if not found/error.
    Requires administrator/root privileges.
    """
    process_name = "N/A"
    try:
        if platform.system() == "Windows":
            # Step 1: Get PID using netstat
            netstat_cmd = ['netstat', '-ano']
            netstat_output = subprocess.check_output(netstat_cmd, text=True, creationflags=_get_subprocess_creation_flags(), stderr=subprocess.PIPE)
            
            # Regex for LISTENING state for TCP, or just any state for UDP (less reliable)
            if protocol == "TCP":
                pid_regex = re.compile(r".*?\s+TCP\s+[\d\.]+:(" + re.escape(str(port_num)) + r")\s+[\d\.]+:[\d]+\s+LISTENING\s+(\d+)")
            else: # UDP
                pid_regex = re.compile(r".*?\s+UDP\s+[\d\.]+:(" + re.escape(str(port_num)) + r")\s+[\d\.]+:[\d]+\s+(\d+)")

            pid = None
            for line in netstat_output.splitlines():
                match = pid_regex.match(line)
                if match:
                    pid = match.group(2) # Extract the PID
                    break

            if pid:
                # Step 2: Get process name using tasklist
                tasklist_cmd = ['tasklist', '/FI', f"PID eq {pid}", '/FO', 'CSV', '/NH']
                tasklist_output = subprocess.check_output(tasklist_cmd, text=True, creationflags=_get_subprocess_creation_flags(), stderr=subprocess.PIPE)
                
                if tasklist_output.strip():
                    process_name_match = re.match(r'^\"([^\"]+)\"', tasklist_output.strip())
                    if process_name_match:
                        process_name = process_name_match.group(1)
                    else:
                        process_name = "Unknown (PID " + pid + ")"
                else:
                    process_name = "No process found (PID " + pid + ")"
            else:
                process_name = "No listening PID"

        else: # Linux/macOS
            cmd = ['lsof', '-i', f"{protocol.lower()}:{port_num}", '-P', '-n']
            lsof_output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, creationflags=_get_subprocess_creation_flags())

            for line in lsof_output.splitlines():
                if f':{port_num}' in line and ('(LISTEN)' in line if protocol == "TCP" else True):
                    parts = line.split()
                    if parts:
                        process_name = parts[0]
                        try:
                            pid = parts[1]
                            # For more detailed process name on Linux
                            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                                cmdline_raw = f.read()
                                full_cmd = cmdline_raw.decode('utf-8', errors='ignore').replace('\x00', ' ').strip()
                                if full_cmd:
                                    process_name = full_cmd
                        except (FileNotFoundError, IndexError):
                            pass # PID not found or error reading cmdline, stick with lsof output
                        break

    except subprocess.CalledProcessError as e:
        if "no process found" in e.stderr.lower():
            process_name = "No process found"
        else:
            log(f"[!] Error getting process info for {protocol} port {port_num}: {e.stderr.strip()}")
            process_name = "Error (Cmd Failed)"
    except FileNotFoundError:
        log(f"[!] Command not found for process info ({'netstat/tasklist' if platform.system() == 'Windows' else 'lsof'}). Cannot determine process info.")
        process_name = "Error (Cmd Missing)"
    except Exception as e:
        log(f"[!] Unexpected error getting process info for {protocol} port {port_num}: {e}")
        process_name = "Error"
    
    return process_name

# Nmap Scanning
def run_os_detection_scan(target_ip):
    """Runs an Nmap OS detection scan on the target IP using Docker."""
    log(f"[+] Running OS Detection scan on {target_ip}...")
    try:
        docker_cmd = [
            'docker', 'run', '--rm',
            '--network=host',
            'uzyexe/nmap',
            '-O', '--osscan-limit', '-T4',
            '-oG', '/tmp/scan_result.txt',
            target_ip
        ]
        subprocess.run(docker_cmd, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] OS Detection scan complete. Results saved to {SCAN_RESULT_OS}")
        return SCAN_RESULT_OS
    except subprocess.CalledProcessError as e:
        log(f"[!] OS Detection scan failed: {e}")
        return None

def run_fragmented_scan(target_ip):
    """Runs a fragmented packet scan on the target IP using Docker."""
    log(f"[+] Running Fragmented Packet scan on {target_ip}...")
    try:
        docker_cmd = [
            'docker', 'run', '--rm',
            '--network=host',
            'uzyexe/nmap',
            '-f', '-sS', '-T4',
            '-oG', '/tmp/scan_result.txt',
            target_ip
        ]
        subprocess.run(docker_cmd, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] Fragmented Packet scan complete. Results saved to {SCAN_RESULT_FRAGMENTED}")
        return SCAN_RESULT_FRAGMENTED
    except subprocess.CalledProcessError as e:
        log(f"[!] Fragmented Packet scan failed: {e}")
        return None

def run_aggressive_scan(target_ip):
    """Runs an aggressive scan on the target IP using Docker."""
    log(f"[+] Running Aggressive scan on {target_ip}...")
    try:
        docker_cmd = [
            'docker', 'run', '--rm',
            '--network=host',
            'uzyexe/nmap',
            '-A', '-T4',
            '-oG', '/tmp/scan_result.txt',
            target_ip
        ]
        subprocess.run(docker_cmd, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] Aggressive scan complete. Results saved to {SCAN_RESULT_AGGRESSIVE}")
        return SCAN_RESULT_AGGRESSIVE
    except subprocess.CalledProcessError as e:
        log(f"[!] Aggressive scan failed: {e}")
        return None

def run_tcp_syn_scan(target_ip):
    """Runs a TCP SYN scan on the target IP using Docker."""
    log(f"[+] Running TCP SYN scan on {target_ip}...")
    try:
        docker_cmd = [
            'docker', 'run', '--rm',
            '--network=host',
            'uzyexe/nmap',
            '-sS', '-T4',
            '-oG', '/tmp/scan_result.txt',
            target_ip
        ]
        subprocess.run(docker_cmd, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] TCP SYN scan complete. Results saved to {SCAN_RESULT_TCP_SYN}")
        return SCAN_RESULT_TCP_SYN
    except subprocess.CalledProcessError as e:
        log(f"[!] TCP SYN scan failed: {e}")
        return None

def run_nmap_scan(target_ip, protocol_type="TCP", scan_type="default"):
    """
    Runs an Nmap scan with the specified parameters using Docker.
    
    Args:
        target_ip: The target IP address or range
        protocol_type: Either "TCP" or "UDP"
        scan_type: Type of scan (default, os, fragmented, aggressive, tcp_syn)
    """
    # Handle special scan types
    if scan_type == "os":
        return run_os_detection_scan(target_ip)
    elif scan_type == "fragmented":
        return run_fragmented_scan(target_ip)
    elif scan_type == "aggressive":
        return run_aggressive_scan(target_ip)
    elif scan_type == "tcp_syn":
        return run_tcp_syn_scan(target_ip)

    # Default scan behavior (TCP/UDP)
    scan_type_display = f"{protocol_type} (Top 1000 Ports)"
    log(f"[+] Running {scan_type_display} scan on {target_ip} using Docker...")

    output_file = SCAN_RESULT_TCP if protocol_type == "TCP" else SCAN_RESULT_UDP

    try:
        # Ensure Docker is available and the image is present
        if not is_docker_available() or not ensure_nmap_docker_image():
            log("[!] Docker is required for scanning but is not available.")
            return None

        # Prepare the Nmap command
        flags = ['-sU'] if protocol_type == "UDP" else ['-sS']
        
        # Add exclusion for Flask app port (5000) if scanning local IP
        local_ips = [get_local_ip(), "127.0.0.1"]
        if target_ip in local_ips or (is_valid_ip_or_range(target_ip) and target_ip.startswith("127.0.0.1")):
            flags.extend(['--exclude-ports', '5000'])

        # Build the Docker command
        docker_cmd = [
            'docker', 'run', '--rm',
            '--network=host',  # Use host network to access local network
            'uzyexe/nmap',
            *flags,
            '-sV', '-Pn', '-T4',  # Standard Nmap options
            '-oG', '/tmp/scan_result.txt',  # Output to a temporary file in the container
            target_ip
        ]
        
        # Run the Docker container
        subprocess.run(docker_cmd, check=True, creationflags=_get_subprocess_creation_flags())
        
        # Copy the results from the container to the host
        log(f"[+] {scan_type_display} scan complete. Results saved to {output_file}")
        return output_file
        
    except subprocess.CalledProcessError as e:
        log(f"[!] {scan_type_display} scan failed: {e}")
        return None
    except FileNotFoundError:
        log("[!] Docker command not found. Please ensure Docker is installed and running.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during {scan_type_display} scan: {e}")
        return None

def extract_open_ports(filename, protocol_type):
    """
    Parses the Nmap greppable output to extract open ports along with their
    detected service and version information, protocol type, and process name.
    Updates the global open_ports dictionary for the specified protocol.
    """
    open_ports[protocol_type].clear()

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                if 'Ports:' in line and 'open' in line:
                    port_details_str = line.split('Ports:')[1].strip()
                    port_entries = port_details_str.split(',')

                    for p_str in port_entries:
                        p_str = p_str.strip()
                        # Ensure 'open' state is present in the port string, regardless of case
                        if 'open' in p_str.lower():
                            parts = p_str.split('/')
                            
                            port_num = parts[0]
                            # Nmap greppable output has protocol at index 2 (e.g., 'tcp', 'udp')
                            protocol = parts[2].upper() 
                            # Service is at index 4, version at index 6
                            service = parts[4].strip() if len(parts) > 4 and parts[4].strip() else 'unknown'
                            version = parts[6].strip() if len(parts) > 6 and parts[6].strip() else ''
                            
                            process_name = "N/A"
                            # Get process info for both TCP and UDP on Linux if lsof supports it
                            # On Windows, get_process_info_for_port handles TCP only
                            process_name = get_process_info_for_port(port_num, protocol=protocol)

                            if protocol == protocol_type: # Only add if it matches the current scan type (TCP or UDP)
                                open_ports[protocol].append({
                                    'port': port_num,
                                    'protocol': protocol,
                                    'service': service,
                                    'version': version,
                                    'process_name': process_name
                                })
                            else:
                                pass
        # IMPORTANT: Send SSE event after all ports for this protocol type have been processed
        # Ensure the data passed is a JSON string
        send_sse_event("ports_updated", json.dumps(get_current_open_ports()))

    except FileNotFoundError:
        log(f"[!] Scan result file '{filename}' not found for {protocol_type} port extraction.")
    except Exception as e:
        log(f"[!] Error extracting {protocol_type} open ports from file: {e}")
    return open_ports[protocol_type]

# Firewall Management
def block_port_windows(port, protocol="TCP"):
    """Blocks a specified port and protocol using Windows Defender Firewall."""
    rule_name = f"Block_NetShield_{protocol}_Port_{port}"
    cmd = [
        "powershell", "-Command",
        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block -Enabled True"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] Firewall rule '{rule_name}' created to block {protocol} port {port}.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False

def is_port_blocked_windows(port, protocol="TCP"):
    """Checks if a specific firewall rule (created by NetShield) exists and is enabled on Windows."""
    rule_name = f"Block_NetShield_{protocol}_Port_{port}"
    cmd = ["powershell", "-Command", f"Get-NetFirewallRule -DisplayName '{rule_name}'"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        return "Enabled" in result.stdout and "True" in result.stdout
    except subprocess.CalledProcessError:
        return False

def block_port_linux(port, protocol="TCP"):
    """Blocks a specified port and protocol using UFW (Uncomplicated Firewall) on Linux."""
    # Ensure UFW is installed and enabled
    try:
        subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
    except FileNotFoundError:
        log("[!] UFW command not found. Please install UFW (e.g., 'sudo apt install ufw'). Cannot block ports.")
        return False
    except subprocess.CalledProcessError:
        log("[!] UFW is not active or configured correctly. Please enable UFW (e.g., 'sudo ufw enable').")
        return False

    # Correct UFW command syntax: ufw deny <port>/<protocol>
    rule_command = ['ufw', 'deny', f"{port}/{protocol.lower()}"]
    try:
        subprocess.run(rule_command, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        log(f"[+] UFW rule created to block {protocol} port {port}.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port} with UFW: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False

def is_port_blocked_linux(port, protocol="TCP"):
    """Checks if a specific UFW rule to block the port exists and is active on Linux."""
    try:
        status_cmd = ['ufw', 'status', 'verbose']
        result = subprocess.run(status_cmd, capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
        
        # Check for rules that explicitly deny the port/protocol
        return f"DENY IN ALLOW OUT Anywhere Anywhere (port {port}/{protocol.lower()})" in result.stdout or \
               f"DENY IN Anywhere Anywhere (port {port}/{protocol.lower()})" in result.stdout or \
               f"DENY IN Anywhere on any (port {port}/{protocol.lower()})" in result.stdout

    except subprocess.CalledProcessError as e:
        log(f"[!] Error checking UFW status: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False
    except FileNotFoundError:
        log("[!] UFW command not found. Cannot verify port block status.")
        return False

def block_port(port, protocol="TCP"):
    """Calls the appropriate OS-specific port blocking function."""
    if platform.system() == "Windows":
        return block_port_windows(port, protocol)
    else:
        return block_port_linux(port, protocol)

def is_port_blocked(port, protocol="TCP"):
    """Calls the appropriate OS-specific port blocked check function."""
    if platform.system() == "Windows":
        return is_port_blocked_windows(port, protocol)
    else:
        return is_port_blocked_linux(port, protocol)

def verify_ports_closed(target_ip):
    """
    Attempts to verify if all detected ports are closed.
    Note: TCP ports are checked via socket connection. UDP verification is limited.
    """
    all_ports_to_verify_info = open_ports["TCP"] + open_ports["UDP"]

    if not all_ports_to_verify_info:
        log("[*] No ports to verify.")
        return

    # If target_ip is a range/CIDR, try to extract a single IP for socket verification
    if '-' in target_ip or '/' in target_ip:
        log("[!] Port verification is most reliable for single IP addresses. Proceeding with the primary IP in the range if detectable.")
        try:
            if '/' in target_ip:
                target_ip_single = target_ip.split('/')[0]
            elif '-' in target_ip:
                target_ip_single = target_ip.split('-')[0]
            else:
                target_ip_single = target_ip
        except Exception:
            target_ip_single = None

        if not is_valid_ip_or_range(target_ip_single):
            log(f"[!] Could not determine a single IP from the target range '{target_ip}' for verification. Skipping verification.")
            return
        else:
            target_ip = target_ip_single

    log(f"[*] Verifying all detected port status on {target_ip}...")
    for p_info in all_ports_to_verify_info:
        port = p_info['port']
        protocol = p_info['protocol']
        if port in whitelisted_ports:
            log(f"[~] Skipping verification for whitelisted {protocol} port {port}.")
            continue
        
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                try:
                    result = s.connect_ex((target_ip, int(port)))
                    if result == 0:
                        log(f"[!] TCP Port {port} (Service: {p_info['service']}) is still OPEN.")
                    else:
                        log(f"[OK] TCP Port {port} (Service: {p_info['service']}) is CLOSED.")
                except Exception as e:
                    log(f"[!] Error verifying TCP port {port}: {e}")
        else:
            log(f"[~] UDP Port {port} (Service: {p_info['service']}) verification via socket is limited. Consider re-scanning with Nmap.")

def add_to_whitelist(ports_str):
    """Adds comma-separated port numbers from the input string to the whitelist."""
    if ports_str:
        ports = [p.strip() for p in ports_str.split(',') if p.strip().isdigit()]
        if ports:
            whitelisted_ports.update(ports)
            save_whitelist() # Save after updating
            log(f"[~] Whitelisted ports updated: {', '.join(ports)}")
            return True
        else:
            log("[!] No valid port numbers found in whitelist input.")
            return False
    else:
        log("[*] Whitelist input is empty.")
        return False

def get_whitelisted_ports():
    """Returns the current list of whitelisted ports."""
    return sorted(list(whitelisted_ports))

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open("agent_log.txt", 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] Log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing log file: {e}")

def get_current_open_ports():
    """Returns the currently detected open ports."""
    return sorted(open_ports["TCP"] + open_ports["UDP"], key=lambda x: int(x['port']))

# Initialization check
if not elevate_if_needed():
    log("[!] Application might not function correctly due to insufficient privileges.")

# Load whitelist on script startup
load_whitelist()

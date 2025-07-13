import subprocess
import os
import sys
import ctypes # Keep for sys.platform check, though not used directly for Linux elevation
import socket
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk # Import ttk for Treeview
import psutil
import threading
import re # For IP address validation

# Globals
# open_ports stores a list of dictionaries, each with 'port', 'service', 'version', 'protocol', and 'process_name'
open_ports = {"TCP": [], "UDP": []}
whitelisted_ports = set()
animation_id = None # Global to store the ID of the current animation job

# Elevation (Linux specific)
def is_admin():
    """Checks if the script is running with root privileges on Linux."""
    return os.geteuid() == 0

def elevate_if_needed():
    """Elevates the script to root privileges if not already running as root on Linux."""
    if not is_admin():
        messagebox.showinfo("Privilege Required", "This application requires root privileges to function correctly (e.g., for port blocking and detailed process info). Please run with 'sudo python3 your_script_name.py'.")
        sys.exit("Root privileges required. Please run with sudo.")

# Logging
def log(message):
    """Logs messages to the GUI's scrolled text area and to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full = f"[{timestamp}] {message}\n"
    log_output.configure(state='normal') # Enable editing
    log_output.insert(tk.END, full)      # Insert the message
    log_output.see(tk.END)               # Scroll to the end
    log_output.configure(state='disabled')# Disable editing
    with open("agent_log.txt", 'a', encoding='utf-8') as f:
        f.write(full)

# Loading Scan Indicators (now only manages text label)
def start_scan_indicators():
    """Starts the loading label text."""
    loading_label.config(text="Scanning...", fg="yellow")

def stop_scan_indicators():
    """Stops the loading label text."""
    loading_label.config(text="Scan complete.", fg="lightgreen")

# GUI State Control
def set_buttons_state(state):
    """Sets the state (normal/disabled) of all main action buttons and controls loading indicator."""
    for btn in buttons:
        btn.configure(state=state)
    add_btn.configure(state=state)
    whitelist_entry.configure(state=state)
    close_btn.configure(state=state)
    target_ip_entry.configure(state=state)
    clear_log_btn.configure(state=state)

    if state == "disabled":
        start_scan_indicators()
    else:
        stop_scan_indicators()

# Network Helpers (Linux specific adjustments)
def get_local_ip():
    """Detects and returns the local IP address (prefers private range addresses)."""
    interfaces = psutil.net_if_addrs()
    for iface, addrs in interfaces.items():
        # Skip common virtual/loopback interfaces on Linux
        if any(x in iface for x in ["lo", "docker", "virbr", "veth", "br-"]):
            continue
        for addr in addrs:
            # Look for IPv4 addresses, preferring private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("192.168.") or ip.startswith("10.") or (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31):
                    return ip
    return "127.0.0.1" # Fallback to loopback if no suitable IP found

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
        subprocess.check_output(['docker', 'info'], text=True, stderr=subprocess.PIPE, creationflags=0) # creationflags=0 for Linux
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
        result = subprocess.run(['docker', 'images', '-q', image_name], capture_output=True, text=True, check=False, creationflags=0)
        if result.stdout.strip():
            log(f"[✓] Docker image {image_name} is already present locally.")
            return True
        else:
            log(f"[*] Docker image {image_name} not found locally. Attempting to pull...")
            pull_result = subprocess.run(['docker', 'pull', image_name], capture_output=True, text=True, check=True, creationflags=0)
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
    Attempts to find the process name listening on a specific TCP/UDP port on Linux.
    Returns the process name or "N/A" if not found/error.
    Requires root privileges for comprehensive information.
    """
    process_name = "N/A"
    try:
        # Use lsof to find the process listening on the port
        cmd = ['lsof', '-i', f"{protocol.lower()}:{port_num}", '-P', '-n']

        lsof_output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, creationflags=0)

        for line in lsof_output.splitlines():
            if f':{port_num}' in line and ('(LISTEN)' in line if protocol == "TCP" else True):
                parts = line.split()
                if parts:
                    process_name = parts[0]
                    try:
                        pid = parts[1]
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
        log("[!] lsof command not found. Please install lsof (e.g., 'sudo apt install lsof'). Cannot determine process info.")
        process_name = "Error (lsof Missing)"
    except Exception as e:
        log(f"[!] Unexpected error getting process info for {protocol} port {port_num}: {e}")
        process_name = "Error"
    
    return process_name

# Nmap Scanning
def run_nmap_scan(target_ip, output_file='scan_result.txt', protocol_type="TCP"):
    """
    Runs an Nmap scan for a specific protocol (TCP or UDP) on the target IP/range
    using a Docker container, including service version detection (-sV) and aggressive timing.
    It scans the top 1000 common ports for the specified protocol (default Nmap behavior).
    """
    scan_type_display = protocol_type.upper()
    log(f"[+] Running {scan_type_display} Nmap scan (Top 1000 Ports) on {target_ip} ...")

    try:
        flags = ['-sU'] if protocol_type == "UDP" else ['-sS'] # -sU for UDP, -sS for TCP SYN scan
        
        cmd = ['docker', 'run', '--rm', 'uzyexe/nmap'] + flags + ['-sV', '-Pn', '-T4', '-oG', '-', target_ip]
        
        result = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, creationflags=0)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)
        log(f"[+] {scan_type_display} Scan complete. Results saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else f"Nmap scan failed with exit code {e.returncode}. No detailed error output."
        log(f"[!] {scan_type_display} Scan failed: {error_message}")
        return None
    except FileNotFoundError:
        log("[!] Docker command not found. Please ensure Docker is installed and in your PATH.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during Nmap scan: {e}")
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
                            process_name = get_process_info_for_port(port_num, protocol=protocol)

                            if protocol == protocol_type: # Only add if it matches the current scan type (TCP or UDP)
                                open_ports[protocol].append({
                                    'port': port_num,
                                    'protocol': protocol,
                                    'service': service,
                                    'version': version,
                                    'process_name': process_name
                                })

    except FileNotFoundError:
        log(f"[!] Scan result file '{filename}' not found for {protocol_type} port extraction.")
    except Exception as e:
        log(f"[!] Error extracting {protocol_type} open ports from file: {e}")
    return open_ports[protocol_type]

# Firewall Management (Linux specific)
def block_port_linux(port, protocol="TCP"):
    """Blocks a specified port and protocol using UFW (Uncomplicated Firewall)."""
    # Ensure UFW is installed and enabled
    try:
        subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True, creationflags=0)
    except FileNotFoundError:
        log("[!] UFW command not found. Please install UFW (e.g., 'sudo apt install ufw'). Cannot block ports.")
        return False
    except subprocess.CalledProcessError:
        log("[!] UFW is not active or configured correctly. Please enable UFW (e.g., 'sudo ufw enable').")
        return False

    # Correct UFW command syntax: ufw deny <port>/<protocol>
    rule_command = ['ufw', 'deny', f"{port}/{protocol.lower()}"]
    try:
        subprocess.run(rule_command, capture_output=True, text=True, check=True, creationflags=0)
        log(f"[+] UFW rule created to block {protocol} port {port}.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port} with UFW: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False

def is_port_blocked_linux(port, protocol="TCP"):
    """Checks if a specific UFW rule to block the port exists and is active."""
    try:
        status_cmd = ['ufw', 'status', 'verbose']
        result = subprocess.run(status_cmd, capture_output=True, text=True, check=True, creationflags=0)
        
        # Check for rules that explicitly deny the port/protocol
        # Example output: DENY IN ALLOW OUT Anywhere on eth0 (port 4444)
        # Or: DENY IN Anywhere (port 4444/tcp)
        return f"DENY IN ALLOW OUT Anywhere Anywhere (port {port}/{protocol.lower()})" in result.stdout or \
               f"DENY IN Anywhere Anywhere (port {port}/{protocol.lower()})" in result.stdout or \
               f"DENY IN Anywhere on any (port {port}/{protocol.lower()})" in result.stdout # More generic check

    except subprocess.CalledProcessError as e:
        log(f"[!] Error checking UFW status: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False
    except FileNotFoundError:
        log("[!] UFW command not found. Cannot verify port block status.")
        return False


# GUI Actions (threaded for responsiveness)
def detect_ip():
    """Initiates local IP detection in a separate thread."""
    def task():
        set_buttons_state("disabled")
        ip = get_local_ip()
        local_ip_var.set(ip)
        log(f"[+] Local IP Detected: {ip}")
        set_buttons_state("normal")
    threading.Thread(target=task, daemon=True).start()

def handle_scan_button_click(protocol_type):
    """Initiates an Nmap scan for the specified protocol on the chosen target in a separate thread."""
    set_buttons_state("disabled")

    def task():
        target = target_ip_var.get().strip()
        if not target:
            target = local_ip_var.get()
            if target == "Not detected" or not target:
                log("[!] No target IP/range entered and local IP not detected. Please detect IP or enter a target.")
                set_buttons_state("normal")
                return
            log(f"[*] Target IP/Range not specified, defaulting to local IP: {target}")
        
        if not is_valid_ip_or_range(target):
            messagebox.showerror("Invalid Input", "Please enter a valid IP address (e.g., 192.168.1.100), CIDR range (e.g., 192.168.1.0/24), or IP range (e.g., 192.168.1.1-254).")
            log(f"[!] Invalid target input: {target}")
            set_buttons_state("normal")
            return

        if not is_docker_available():
            messagebox.showerror("Docker Issue", "Docker is not available or not running. Please check the log for details.")
            set_buttons_state("normal")
            return
        
        if not ensure_nmap_docker_image():
            messagebox.showerror("Docker Image Error", "Failed to ensure Nmap Docker image is available. Please check the log for details.")
            set_buttons_state("normal")
            return

        file = run_nmap_scan(target, protocol_type=protocol_type)
        if file:
            extract_open_ports(file, protocol_type)
            update_ports_display()
        set_buttons_state("normal")
    threading.Thread(target=task, daemon=True).start()

def handle_block():
    """Initiates blocking of all detected open ports (TCP and UDP) in a separate thread."""
    def task():
        set_buttons_state("disabled")
        all_ports_to_block_info = open_ports["TCP"] + open_ports["UDP"]
        
        if not all_ports_to_block_info:
            log("[*] No open ports detected to block.")
            set_buttons_state("normal")
            return

        log(f"[*] Attempting to block {len(all_ports_to_block_info)} detected ports...")
        for p_info in all_ports_to_block_info:
            port = p_info['port']
            protocol = p_info['protocol']
            if port in whitelisted_ports:
                log(f"[~] Skipping whitelisted {protocol} port {port}.")
                continue
            
            # Use Linux blocking function
            success = block_port_linux(port, protocol=protocol)
            if success and is_port_blocked_linux(port, protocol=protocol):
                log(f"[✓] {protocol} Port {port} successfully blocked and verified.")
            else:
                log(f"[x] {protocol} Port {port} could not be verified as blocked. Manual check may be needed.")
        set_buttons_state("normal")
    threading.Thread(target=task, daemon=True).start()

def verify_ports_closed():
    """
    Attempts to verify if all detected ports are closed.
    Note: TCP ports are checked via socket connection. UDP verification is limited.
    """
    def task():
        set_buttons_state("disabled")
        all_ports_to_verify_info = open_ports["TCP"] + open_ports["UDP"]

        if not all_ports_to_verify_info:
            log("[*] No ports to verify.")
            set_buttons_state("normal")
            return

        target = target_ip_var.get().strip()
        if not target:
            target = local_ip_var.get()
            if target == "Not detected" or not target:
                log("[!] Cannot verify ports without a detected IP address or a target entered.")
                set_buttons_state("normal")
                return
        
        if '-' in target or '/' in target:
            log("[!] Port verification is most reliable for single IP addresses. Proceeding with the primary IP in the range if detectable.")
            try:
                if '/' in target:
                    target_ip = target.split('/')[0]
                elif '-' in target:
                    target_ip = target.split('-')[0]
                else:
                    target_ip = target
            except Exception:
                target_ip = None

            if not is_valid_ip_or_range(target_ip):
                log(f"[!] Could not determine a single IP from the target range '{target}' for verification. Skipping verification.")
                set_buttons_state("normal")
                return
            else:
                target = target_ip

        log(f"[*] Verifying all detected port status on {target}...")
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
                        result = s.connect_ex((target, int(port)))
                        if result == 0:
                            log(f"[!] TCP Port {port} (Service: {p_info['service']}) is still OPEN.")
                        else:
                            log(f"[OK] TCP Port {port} (Service: {p_info['service']}) is CLOSED.")
                    except Exception as e:
                        log(f"[!] Error verifying TCP port {port}: {e}")
            else:
                log(f"[~] UDP Port {port} (Service: {p_info['service']}) verification via socket is limited. Consider re-scanning with Nmap.")
        set_buttons_state("normal")
    threading.Thread(target=task, daemon=True).start()

def add_to_whitelist():
    """Adds comma-separated port numbers from the input entry to the whitelist."""
    raw_input = whitelist_entry.get().strip()
    if raw_input:
        ports = [p.strip() for p in raw_input.split(',') if p.strip().isdigit()]
        if ports:
            whitelisted_ports.update(ports)
            whitelist_var.set(", ".join(sorted(list(whitelisted_ports))))
            log(f"[~] Whitelisted ports updated: {', '.join(ports)}")
        else:
            log("[!] No valid port numbers found in whitelist input.")
        whitelist_entry.delete(0, tk.END)
    else:
        log("[*] Whitelist input is empty.")

def update_ports_display():
    """Updates the GUI's Treeview with detected open ports and their services/versions/process names."""
    for item in tree.get_children():
        tree.delete(item)

    all_ports = sorted(open_ports["TCP"] + open_ports["UDP"], key=lambda x: int(x['port']))
    
    if not all_ports:
        log("[*] No open TCP or UDP ports detected to display.") # More specific log message
        return

    for i, p_info in enumerate(all_ports, 1):
        port = p_info.get('port', 'N/A')
        protocol = p_info.get('protocol', 'N/A')
        service = p_info.get('service', 'N/A')
        version = p_info.get('version', '')
        process_name = p_info.get('process_name', 'N/A')

        tree.insert('', tk.END, values=(i, port, protocol, service, version, process_name))

def clear_log():
    """Clears the content of the log output text area."""
    log_output.configure(state='normal')
    log_output.delete(1.0, tk.END)
    log_output.configure(state='disabled')
    log("[*] Log cleared by user.")


if __name__ == "__main__":
    elevate_if_needed() # Ensure script runs with root privileges on Linux

    root = tk.Tk()
    root.title("NetShield - Port Scanner & Blocker (Linux)")
    root.geometry("800x520") # Fixed window size remains for stability
    root.configure(bg="#1e1e1e") # Dark background

    # Tkinter variables for dynamic label updates
    local_ip_var = tk.StringVar(value="Not detected")
    target_ip_var = tk.StringVar(value="")
    whitelist_var = tk.StringVar(value="None")

    # LEFT PANEL (Buttons and Whitelist)
    left_frame = tk.Frame(root, bg="#1e1e1e", width=280)
    left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0), pady=10)

    # Brand/Logo
    brand_frame = tk.Frame(left_frame, bg="#1e1e1e")
    brand_frame.pack(pady=(0, 15)) # Reduced pady
    tk.Label(brand_frame, text="🛡", font=("Segoe UI Emoji", 24), bg="#1e1e1e", fg="#00e6e6").pack(side=tk.LEFT) # Smaller font
    tk.Label(brand_frame, text="NetShield", font=("Segoe UI", 18, "bold"), bg="#1e1e1e", fg="#00e6e6", padx=10).pack(side=tk.LEFT) # Smaller font

    # Main Action Buttons
    buttons = []
    btn_style = {
        "font": ("Segoe UI", 10), # Reduced font
        "width": 25,
        "anchor": "w",
        "padx": 5,
        "bg": "#3c3c3c",
        "fg": "white",
        "relief": "groove",
        "activebackground": "#555",
        "activeforeground": "white"
    }

    # Create buttons dynamically
    for idx, (text, cmd) in enumerate([
        ("1. Detect Local IP", detect_ip),
        ("2A. Scan TCP Ports (Top 1000)", lambda: handle_scan_button_click("TCP")),
        ("2B. Scan UDP Ports (Top 1000)", lambda: handle_scan_button_click("UDP")),
        ("3. Block Detected Ports", handle_block),
        ("4. Verify Ports Are Closed", verify_ports_closed)
    ]):
        btn = tk.Button(left_frame, text=text, command=cmd, **btn_style)
        btn.pack(pady=3) # Reduced pady between buttons
        buttons.append(btn)

    # Scan Status Label
    loading_label = tk.Label(left_frame, text="Ready", font=("Segoe UI", 10, "bold"), bg="#1e1e1e", fg="lightgreen") # Reduced font
    loading_label.pack(pady=(8, 8)) # Reduced pady

    # Target IP Input Section
    target_ip_frame = tk.Frame(left_frame, bg="#1e1e1e")
    target_ip_frame.pack(pady=(15, 5), fill='x') # Reduced pady
    tk.Label(target_ip_frame, text="Target IP / Range:", fg="white", bg="#1e1e1e", font=("Segoe UI", 9)).pack(anchor='w') # Reduced font
    target_ip_entry = tk.Entry(target_ip_frame, textvariable=target_ip_var, font=("Segoe UI", 9), bg="#333", fg="white", insertbackground="white", width=28, relief="flat", bd=2) # Reduced font
    target_ip_entry.pack(pady=3) # Reduced pady
    buttons.append(target_ip_entry)

    # Whitelist Section
    whitelist_frame = tk.Frame(left_frame, bg="#1e1e1e")
    whitelist_frame.pack(pady=(10, 5), fill='x') # Reduced pady
    tk.Label(whitelist_frame, text="Whitelist Ports (comma-separated):", fg="white", bg="#1e1e1e", font=("Segoe UI", 9)).pack(anchor='w') # Reduced font
    whitelist_entry = tk.Entry(whitelist_frame, font=("Segoe UI", 9), bg="#333", fg="white", insertbackground="white", width=28, relief="flat", bd=2) # Reduced font
    whitelist_entry.pack(pady=3) # Reduced pady
    add_btn = tk.Button(whitelist_frame, text="Add to Whitelist", command=add_to_whitelist, font=("Segoe UI", 9), bg="#444", fg="white", relief="flat", activebackground="#666", activeforeground="white") # Reduced font
    add_btn.pack()

    # Close GUI Button
    close_btn = tk.Button(left_frame, text="Close GUI", command=root.destroy, font=("Segoe UI", 10), width=25, # Reduced font
                        bg="#a00000", fg="white", relief="groove", activebackground="#c00000", activeforeground="white")
    close_btn.pack(side=tk.BOTTOM, pady=10)
    buttons.append(close_btn)

    # RIGHT PANEL (Information Display and Log)
    right_frame = tk.Frame(root, bg="#1e1e1e")
    right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Information Display Frame
    info_frame = tk.Frame(right_frame, bg="#1e1e1e")
    info_frame.pack(anchor='nw', pady=(0, 10), fill='x')

    section_font = ("Segoe UI", 11) # Reduced font
    tk.Label(info_frame, text="Local IP:", bg="#1e1e1e", fg="white", font=section_font).pack(anchor='w')
    tk.Label(info_frame, textvariable=local_ip_var, bg="#1e1e1e", fg="lightblue", font=("Segoe UI", 11, "bold")).pack(anchor='w', pady=(0, 3)) # Reduced font, pady

    # Open Ports Display (Treeview with new Process column)
    tk.Label(info_frame, text="Open Ports (Service & Version):", bg="#1e1e1e", fg="white", font=section_font).pack(anchor='w', pady=(0, 3)) # Reduced pady

    # Define columns
    columns = ('#', 'Port', 'Protocol', 'Service', 'Version', 'Process')
    tree = ttk.Treeview(info_frame, columns=columns, show='headings', height=7) # Height remains 7 for readability

    # Configure column headings
    tree.heading('#', text='No.', anchor=tk.CENTER)
    tree.heading('Port', text='Port', anchor=tk.W)
    tree.heading('Protocol', text='Protocol', anchor=tk.W)
    tree.heading('Service', text='Service', anchor=tk.W)
    tree.heading('Version', text='Version', anchor=tk.W)
    tree.heading('Process', text='Process', anchor=tk.W)

    # Configure column widths (slightly adjusted for compactness if needed)
    tree.column('#', width=35, anchor=tk.CENTER, stretch=tk.NO)
    tree.column('Port', width=55, anchor=tk.W, stretch=tk.NO)
    tree.column('Protocol', width=65, anchor=tk.W, stretch=tk.NO)
    tree.column('Service', width=110, anchor=tk.W)
    tree.column('Version', width=110, anchor=tk.W)
    tree.column('Process', width=140, anchor=tk.W)

    # Style for the Treeview to match the dark theme
    style = ttk.Style()
    style.theme_use("default")
    style.configure("Treeview",
                    background="#2d2d2d",
                    foreground="white",
                    font=("Segoe UI", 9), # Reduced font for treeview content
                    fieldbackground="#2d2d2d",
                    bordercolor="#3c3c3c",
                    lightcolor="#3c3c3c",
                    darkcolor="#1e1e1e",
                    rowheight=22) # Reduced row height

    style.map('Treeview',
            background=[('selected', '#007ACC')],
            foreground=[('selected', 'white')])

    style.configure("Treeview.Heading",
                    font=("Segoe UI", 9, "bold"), # Reduced font for headings
                    background="#3c3c3c",
                    foreground="white",
                    relief="flat",
                    bordercolor="#3c3c3c")

    style.map("Treeview.Heading",
            background=[('active', '#555')])

    tree.pack(fill='x', pady=(0, 5))

    tk.Label(info_frame, text="Whitelisted Ports:", bg="#1e1e1e", fg="white", font=section_font).pack(anchor='w', pady=(0, 0))
    tk.Label(info_frame, textvariable=whitelist_var, bg="#1e1e1e", fg="lightgreen", font=("Consolas", 11)).pack(anchor='w', pady=(0, 5)) # Reduced font

    # Log Output Section with Clear Log Button
    log_controls_frame = tk.Frame(right_frame, bg="#1e1e1e")
    log_controls_frame.pack(anchor='w', pady=(5, 0), fill='x')

    tk.Label(log_controls_frame, text="Log Output", bg="#1e1e1e", fg="white", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT) # Reduced font
    clear_log_btn = tk.Button(log_controls_frame, text="Clear Log", command=clear_log, font=("Segoe UI", 8), # Reduced font
                            bg="#444", fg="white", relief="flat", activebackground="#666", activeforeground="white")
    clear_log_btn.pack(side=tk.RIGHT, padx=3) # Reduced padx

    log_output = scrolledtext.ScrolledText(right_frame, width=80, height=12, font=("Courier New", 9), bg="#2d2d2d", fg="white", borderwidth=0, relief="flat", insertbackground="white") # Reduced font
    log_output.pack(fill='both', expand=True, pady=(3,0)) # Reduced pady
    log_output.configure(state='disabled')


    root.mainloop()

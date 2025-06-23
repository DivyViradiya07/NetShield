import subprocess
import os
import sys
import ctypes
import socket
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk # Import ttk for Treeview
import psutil
import threading

# Globals
# open_ports stores a list of dictionaries, each with 'port', 'service', 'version', and 'protocol'
open_ports = {"TCP": [], "UDP": []}
current_protocol = "TCP"  # Default protocol state (can be TCP, UDP, or Combined conceptually)
whitelisted_ports = set()

# Elevation
def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def elevate_if_needed():
    """Elevates the script to administrator privileges if not already running as admin."""
    if not is_admin():
        # Re-launch the script with 'runas' verb for elevation
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}"', None, 1)
        sys.exit()

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

# GUI State Control
def set_buttons_state(state):
    """Sets the state (normal/disabled) of all main action buttons."""
    for btn in buttons:
        btn.configure(state=state)
    add_btn.configure(state=state)
    whitelist_entry.configure(state=state)
    close_btn.configure(state=state) # Add the close button to state control

# Network Helpers
def get_local_ip():
    """Detects and returns the local IP address (prefers 192.168.x.x addresses)."""
    interfaces = psutil.net_if_addrs()
    for iface, addrs in interfaces.items():
        # Skip virtual, VMware, Loopback, etc. interfaces
        if any(x in iface for x in ["Virtual", "VMware", "Loopback", "vEthernet", "WSL"]):
            continue
        for addr in addrs:
            # Look for IPv4 addresses, preferring private range (192.168.x.x)
            if addr.family == socket.AF_INET and addr.address.startswith("192.168."):
                return addr.address
    return "127.0.0.1" # Fallback to loopback if no suitable IP found

def is_docker_available():
    """Checks if Docker is installed and accessible on the system."""
    try:
        # Check if docker command itself is available AND if the daemon is reachable
        subprocess.check_output(['docker', 'info'], text=True, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Docker daemon not running or not accessible: {e.stderr.strip() if e.stderr else 'No stderr output'}")
        return False
    except FileNotFoundError:
        log("[!] Docker command not found. Please ensure Docker Desktop is installed and in your PATH.")
        return False
    except Exception as e:
        log(f"[!] An unexpected error occurred while checking Docker: {e}")
        return False

# Nmap Scanning
def run_nmap_scan(target_ip, output_file='scan_result.txt', protocol_type="TCP"):
    """
    Runs an Nmap scan for a specific protocol (TCP or UDP) on the target IP
    using a Docker container, including service version detection (-sV) and aggressive timing.
    It now scans the top 1000 common ports for the specified protocol (default Nmap behavior).
    """
    scan_type_display = protocol_type.upper()
    # Changed log message to reflect "Top 1000 Ports"
    log(f"[+] Running {scan_type_display} Nmap scan (Top 1000 Ports) on {target_ip} ...")

    try:
        flags = ['-sU'] if protocol_type == "UDP" else ['-sS'] # -sU for UDP, -sS for TCP SYN scan
        
        # Include -sV for service detection, -Pn to skip host discovery, -T4 for aggressive timing.
        # Removed '-p', '1-65535' to revert to Nmap's default top 1000 common ports scan.
        cmd = ['docker', 'run', '--rm', 'uzyexe/nmap'] + flags + ['-sV', '-Pn', '-T4', '-oG', '-', target_ip]
        
        result = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE) # Capture stdout and stderr
        with open(output_file, 'w', encoding='utf-8') as f: # Save raw Nmap output
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
    detected service and version information and protocol type.
    Updates the global open_ports dictionary for the specified protocol.
    """
    # Clear previous scan results for the specific protocol
    open_ports[protocol_type].clear()

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                if 'Ports:' in line and 'open' in line:
                    port_details_str = line.split('Ports:')[1].strip()
                    port_entries = port_details_str.split(',')

                    for p_str in port_entries:
                        p_str = p_str.strip()
                        if 'open' in p_str: # Ensure the port is marked as open
                            parts = p_str.split('/')
                            # Expected format: port/state/protocol//service//version/
                            if len(parts) >= 7:
                                port_num = parts[0]
                                protocol = parts[2].upper()
                                service = parts[4].strip() if parts[4].strip() else 'unknown'
                                version = parts[6].strip() if parts[6].strip() else ''

                                # Ensure we only add to the correct protocol list
                                if protocol == protocol_type:
                                    open_ports[protocol].append({
                                        'port': port_num,
                                        'protocol': protocol,
                                        'service': service,
                                        'version': version
                                    })
                            elif len(parts) >= 3:
                                port_num = parts[0]
                                protocol = parts[2].upper()
                                if protocol == protocol_type:
                                    open_ports[protocol].append({
                                        'port': port_num,
                                        'protocol': protocol,
                                        'service': 'N/A',
                                        'version': ''
                                    })

    except FileNotFoundError:
        log(f"[!] Scan result file '{filename}' not found for {protocol_type} port extraction.")
    except Exception as e:
        log(f"[!] Error extracting {protocol_type} open ports from file: {e}")
    return open_ports[protocol_type] # Return the updated list for the protocol

# Firewall Management
def block_port_windows(port, protocol="TCP"):
    """Blocks a specified port and protocol using Windows Defender Firewall."""
    rule_name = f"Block_NetShield_{protocol}_Port_{port}" # Unique rule name
    cmd = [
        "powershell", "-Command",
        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block -Enabled True"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        log(f"[+] Firewall rule '{rule_name}' created to block {protocol} port {port}.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to block {protocol} port {port}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        return False

def is_port_blocked(port, protocol="TCP"):
    """Checks if a specific firewall rule (created by NetShield) exists and is enabled."""
    rule_name = f"Block_NetShield_{protocol}_Port_{port}"
    cmd = ["powershell", "-Command", f"Get-NetFirewallRule -DisplayName '{rule_name}'"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Check for 'Enabled' property in the output. PowerShell Get-NetFirewallRule usually outputs table.
        return "Enabled" in result.stdout and "True" in result.stdout # Ensure it's explicitly enabled
    except subprocess.CalledProcessError:
        return False # Rule not found or error occurred

# GUI Actions (threaded for responsiveness)
def detect_ip():
    """Initiates IP detection in a separate thread."""
    def task():
        set_buttons_state("disabled")
        ip = get_local_ip()
        ip_var.set(ip)
        log(f"[+] IP Detected: {ip}")
        set_buttons_state("normal")
    threading.Thread(target=task, daemon=True).start()

def handle_scan_button_click(protocol_type):
    """Initiates an Nmap scan for the specified protocol in a separate thread."""
    def task():
        set_buttons_state("disabled")
        if not is_docker_available():
            messagebox.showerror("Docker Issue", "Docker is not available or not running. Please check the log for details.")
            set_buttons_state("normal")
            return
        target = ip_var.get()
        if target == "Not detected" or not target:
            log("[!] Please detect IP address first.")
            set_buttons_state("normal")
            return

        file = run_nmap_scan(target, protocol_type=protocol_type) # Call with protocol type
        if file:
            extract_open_ports(file, protocol_type) # Extract specifically for this protocol
            update_ports_display() # Update display with *all* currently known ports
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
            protocol = p_info['protocol'] # Use the protocol from the stored info
            if port in whitelisted_ports:
                log(f"[~] Skipping whitelisted {protocol} port {port}.")
                continue
            
            success = block_port_windows(port, protocol=protocol)
            if success and is_port_blocked(port, protocol=protocol):
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

        ip = ip_var.get()
        if ip == "Not detected" or not ip:
            log("[!] Cannot verify ports without a detected IP address.")
            set_buttons_state("normal")
            return

        log(f"[*] Verifying all detected port status on {ip}...")
        for p_info in all_ports_to_verify_info:
            port = p_info['port']
            protocol = p_info['protocol'] # Use the protocol from the stored info
            if port in whitelisted_ports:
                log(f"[~] Skipping verification for whitelisted {protocol} port {port}.")
                continue
            
            if protocol == "TCP":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1) # Short timeout for quick checks
                    try:
                        # connect_ex returns 0 if connection succeeds (port is open)
                        result = s.connect_ex((ip, int(port)))
                        if result == 0:
                            log(f"[!] TCP Port {port} (Service: {p_info['service']}) is still OPEN.")
                        else:
                            log(f"[OK] TCP Port {port} (Service: {p_info['service']}) is CLOSED.")
                    except Exception as e:
                        log(f"[!] Error verifying TCP port {port}: {e}")
            else: # For UDP, direct socket connection is not reliable for "closed" state
                log(f"[~] UDP Port {port} (Service: {p_info['service']}) verification via socket is limited. Consider re-scanning with Nmap.")
        set_buttons_state("normal")
    threading.Thread(target=task, daemon=True).start()

def add_to_whitelist():
    """Adds comma-separated port numbers from the input entry to the whitelist."""
    raw_input = whitelist_entry.get().strip()
    if raw_input:
        # Split by comma, strip spaces, filter for digits only
        ports = [p.strip() for p in raw_input.split(',') if p.strip().isdigit()]
        if ports:
            whitelisted_ports.update(ports) # Add to the set
            # Update the whitelist display, sorted for consistency
            whitelist_var.set(", ".join(sorted(list(whitelisted_ports))))
            log(f"[~] Whitelisted ports updated: {', '.join(ports)}")
        else:
            log("[!] No valid port numbers found in whitelist input.")
        whitelist_entry.delete(0, tk.END) # Clear the input field
    else:
        log("[*] Whitelist input is empty.")

def update_ports_display():
    """Updates the GUI's Treeview with detected open ports and their services/versions."""
    # Clear existing entries in the Treeview
    for item in tree.get_children():
        tree.delete(item)

    all_ports = sorted(open_ports["TCP"] + open_ports["UDP"], key=lambda x: int(x['port'])) # Sort by port number
    
    if not all_ports:
        log("[*] No open ports detected to display.")
        return

    # Add a sequential number to each row
    for i, p_info in enumerate(all_ports, 1):
        port = p_info.get('port', 'N/A')
        protocol = p_info.get('protocol', 'N/A')
        service = p_info.get('service', 'N/A')
        version = p_info.get('version', '')
        
        # Insert data into the Treeview
        tree.insert('', tk.END, values=(i, port, protocol, service, version))

# GUI Setup
elevate_if_needed() # Ensure script runs with admin privileges

root = tk.Tk()
root.title("NetShield - Port Scanner & Blocker")
root.geometry("1000x550") # Fixed window size
root.configure(bg="#1e1e1e") # Dark background

# Tkinter variables for dynamic label updates
ip_var = tk.StringVar(value="Not detected")
whitelist_var = tk.StringVar(value="None")

# LEFT PANEL (Buttons and Whitelist)
left_frame = tk.Frame(root, bg="#1e1e1e", width=280)
left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0), pady=10)

# Brand/Logo
brand_frame = tk.Frame(left_frame, bg="#1e1e1e")
brand_frame.pack(pady=(0, 20))
tk.Label(brand_frame, text="🛡", font=("Segoe UI Emoji", 26), bg="#1e1e1e", fg="#00e6e6").pack(side=tk.LEFT)
tk.Label(brand_frame, text="NetShield", font=("Segoe UI", 20, "bold"), bg="#1e1e1e", fg="#00e6e6", padx=10).pack(side=tk.LEFT)

# Main Action Buttons
buttons = []
# Define a consistent style for buttons
btn_style = {
    "font": ("Segoe UI", 11),
    "width": 25,
    "anchor": "w", # Align text to west (left)
    "padx": 5,
    "bg": "#3c3c3c", # Dark gray background
    "fg": "white",   # White text
    "relief": "groove", # Grooved border
    "activebackground": "#555", # Darker on click
    "activeforeground": "white"
}

# Create buttons dynamically
for idx, (text, cmd) in enumerate([
    ("1. Detect IP", detect_ip),
    # Changed text to reflect "Top 1000" and ensured no -p flag is added
    ("2A. Scan TCP Ports (Top 1000)", lambda: handle_scan_button_click("TCP")),
    ("2B. Scan UDP Ports (Top 1000)", lambda: handle_scan_button_click("UDP")),
    ("3. Block Detected Ports", handle_block),
    ("4. Verify Ports Are Closed", verify_ports_closed)
]):
    btn = tk.Button(left_frame, text=text, command=cmd, **btn_style)
    btn.pack(pady=(5 if idx != 0 else 0)) # Add padding, except for the first button
    buttons.append(btn)

# Whitelist Section
whitelist_frame = tk.Frame(left_frame, bg="#1e1e1e")
whitelist_frame.pack(pady=(25, 5), fill='x')
tk.Label(whitelist_frame, text="Whitelist Ports (comma-separated):", fg="white", bg="#1e1e1e", font=("Segoe UI", 10)).pack(anchor='w')
whitelist_entry = tk.Entry(whitelist_frame, font=("Segoe UI", 10), bg="#333", fg="white", insertbackground="white", width=28, relief="flat", bd=2)
whitelist_entry.pack(pady=5)
add_btn = tk.Button(whitelist_frame, text="Add to Whitelist", command=add_to_whitelist, font=("Segoe UI", 10), bg="#444", fg="white", relief="flat", activebackground="#666", activeforeground="white")
add_btn.pack()

# Close GUI Button
close_btn = tk.Button(left_frame, text="Close GUI", command=root.destroy, font=("Segoe UI", 11), width=25,
                      bg="#a00000", fg="white", relief="groove", activebackground="#c00000", activeforeground="white")
close_btn.pack(side=tk.BOTTOM, pady=10)
buttons.append(close_btn) # Add to the list so its state can be controlled

# RIGHT PANEL (Information Display and Log)
right_frame = tk.Frame(root, bg="#1e1e1e")
right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

# Information Display Frame
info_frame = tk.Frame(right_frame, bg="#1e1e1e")
info_frame.pack(anchor='nw', pady=(0, 10), fill='x')

section_font = ("Segoe UI", 12)
# Detected IP Display
tk.Label(info_frame, text="Detected IP:", bg="#1e1e1e", fg="white", font=section_font).pack(anchor='w')
tk.Label(info_frame, textvariable=ip_var, bg="#1e1e1e", fg="lightblue", font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=(0, 5))

# Open Ports Display (now a Treeview)
tk.Label(info_frame, text="Open Ports (Service & Version):", bg="#1e1e1e", fg="white", font=section_font).pack(anchor='w', pady=(0, 5))

# Treeview for displaying open ports in a tabular format
# Define columns
columns = ('#', 'Port', 'Protocol', 'Service', 'Version')
tree = ttk.Treeview(info_frame, columns=columns, show='headings', height=7) # Adjust height as needed

# Configure column headings
tree.heading('#', text='No.', anchor=tk.CENTER)
tree.heading('Port', text='Port', anchor=tk.W)
tree.heading('Protocol', text='Protocol', anchor=tk.W)
tree.heading('Service', text='Service', anchor=tk.W)
tree.heading('Version', text='Version', anchor=tk.W)

# Configure column widths (approximate, Treeview adjusts)
tree.column('#', width=40, anchor=tk.CENTER, stretch=tk.NO)
tree.column('Port', width=60, anchor=tk.W, stretch=tk.NO)
tree.column('Protocol', width=70, anchor=tk.W, stretch=tk.NO)
tree.column('Service', width=120, anchor=tk.W)
tree.column('Version', width=180, anchor=tk.W)

# Style for the Treeview to match the dark theme
style = ttk.Style()
style.theme_use("default") # Use a default theme to customize from
style.configure("Treeview",
                background="#2d2d2d", # Background of the content area
                foreground="white",   # Text color
                fieldbackground="#2d2d2d", # Background of the cell
                bordercolor="#3c3c3c", # Border color of cells
                lightcolor="#3c3c3c", # Lighter part of borders
                darkcolor="#1e1e1e",  # Darker part of borders
                rowheight=25) # Height of each row

style.map('Treeview',
          background=[('selected', '#007ACC')], # Selected row background (blue)
          foreground=[('selected', 'white')]) # Selected row text color

style.configure("Treeview.Heading",
                font=("Segoe UI", 10, "bold"),
                background="#3c3c3c", # Header background
                foreground="white",   # Header text color
                relief="flat",
                bordercolor="#3c3c3c") # Header border color

style.map("Treeview.Heading",
          background=[('active', '#555')]) # Header background on hover

tree.pack(fill='x', pady=(0, 5)) # Pack the Treeview

# Whitelisted Ports Display
tk.Label(info_frame, text="Whitelisted Ports:", bg="#1e1e1e", fg="white", font=section_font).pack(anchor='w', pady=(0, 5))
tk.Label(info_frame, textvariable=whitelist_var, bg="#1e1e1e", fg="lightgreen", font=("Consolas", 12)).pack(anchor='w', pady=(0, 5))

# Log Output Section
tk.Label(info_frame, text="Log Output", bg="#1e1e1e", fg="white", font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=(10, 0))
log_output = scrolledtext.ScrolledText(right_frame, width=80, height=20, font=("Courier New", 10), bg="#2d2d2d", fg="white", borderwidth=0, relief="flat", insertbackground="white")
log_output.pack(fill='both', expand=True)
log_output.configure(state='disabled') # Initially disabled for user input

root.mainloop() # Start the Tkinter event loop

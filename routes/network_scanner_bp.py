from flask import Flask, render_template, jsonify, request, Response
from flask import Blueprint
import threading
import json
import time
import os

from Services import network_scanner

network_scanner_bp = Blueprint('network_scanner_bp', __name__)

# Add this route to handle the /network_scanner URL
@network_scanner_bp.route('/')
def network_scanner_page():
    """Renders the network scanner page."""
    return render_template('network_scanner.html')  # Make sure this template exists

@network_scanner_bp.route('/local_ip', methods=['GET'])
def get_local_ip_route():
    """API endpoint to detect and return the local IP address."""
    local_ip = network_scanner.get_local_ip()
    network_scanner.log(f"[*] Local IP requested: {local_ip}")
    return jsonify({"local_ip": local_ip})

@network_scanner_bp.route('/scan', methods=['POST'])
def scan_ports():
    """
    API endpoint to initiate a port scan (TCP or UDP) with optional scan type.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_ip = data.get('target_ip')
    protocol_type = data.get('protocol_type', 'TCP').upper()  # Default to TCP
    scan_type = data.get('scan_type', 'default')  # Default to standard scan

    # Validate scan type
    valid_scan_types = ['default', 'os', 'fragmented', 'aggressive', 'tcp_syn']
    if scan_type not in valid_scan_types:
        return jsonify({"status": "error", "message": "Invalid scan type specified."}), 400

    # If target_ip is empty, try to use local IP
    if not target_ip:
        target_ip = network_scanner.get_local_ip()
        if target_ip == "127.0.0.1" and not network_scanner.is_valid_ip_or_range(target_ip):
            network_scanner.log("[!] No target IP/range entered and local IP not detected. Please detect IP or enter a target.")
            return jsonify({"status": "error", "message": "No target IP/range provided and local IP not detected."}), 400
        network_scanner.log(f"[*] Target IP/Range not specified, defaulting to local IP: {target_ip}")

    if not network_scanner.is_valid_ip_or_range(target_ip):
        network_scanner.log(f"[!] Invalid target input: {target_ip}")
        return jsonify({"status": "error", "message": "Please enter a valid IP address, CIDR range, or IP range."}), 400

    # For OS detection, we don't need Docker
    if scan_type != 'os' and not network_scanner.is_docker_available():
        network_scanner.log("[!] Docker is not available or not running. Cannot perform scan.")
        return jsonify({"status": "error", "message": "Docker is not available or not running. Please check the log for details."}), 500
    
    if scan_type != 'os' and not network_scanner.ensure_nmap_docker_image():
        network_scanner.log("[!] Failed to ensure Nmap Docker image is available. Cannot perform scan.")
        return jsonify({"status": "error", "message": "Failed to ensure Nmap Docker image is available. Please check the log for details."}), 500

    # Function to run in a separate thread
    def scan_task():
        network_scanner.log(f"[*] Starting {scan_type.upper()} {protocol_type} scan for {target_ip}...")
        output_file = network_scanner.run_nmap_scan(target_ip, protocol_type=protocol_type, scan_type=scan_type)
        if output_file:
            network_scanner.extract_open_ports(output_file, protocol_type)
            network_scanner.log(f"[+] {scan_type.upper()} {protocol_type} scan and extraction complete.")
        else:
            network_scanner.log(f"[!] {scan_type.upper()} {protocol_type} scan failed.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"{scan_type.upper()} scan for {target_ip} ({protocol_type}) initiated."})

@network_scanner_bp.route('/scan/advanced', methods=['POST'])
def advanced_scan():
    """
    API endpoint for advanced scan types that require special parameters.
    Currently supports: os, fragmented, aggressive, tcp_syn
    """
    data = request.get_json()
    target_ip = data.get('target_ip')
    scan_type = data.get('scan_type')
    
    # For advanced scans, we only support TCP protocol
    protocol_type = 'TCP'
    
    # Validate required parameters
    if not target_ip or not scan_type:
        return jsonify({"status": "error", "message": "Target IP and scan type are required."}), 400
        
    # Validate scan type
    valid_scan_types = ['os', 'fragmented', 'aggressive', 'tcp_syn']
    if scan_type not in valid_scan_types:
        return jsonify({"status": "error", "message": "Invalid scan type. Must be one of: " + ", ".join(valid_scan_types)}), 400
    
    # Use the standard scan endpoint with the specified scan type
    return scan_ports()

@network_scanner_bp.route('/open_ports', methods=['GET'])
def get_open_ports_route():
    """API endpoint to get the currently detected open ports."""
    ports = network_scanner.get_current_open_ports()
    return jsonify({"open_ports": ports})

@network_scanner_bp.route('/block_ports', methods=['POST'])
def block_ports_route():
    """
    API endpoint to initiate blocking of all detected open ports.
    Runs the blocking in a separate thread.
    """
    if not network_scanner.is_admin():
        network_scanner.log("[!] Insufficient privileges to block ports. Please run the server as administrator/root.")
        return jsonify({"status": "error", "message": "Insufficient privileges to block ports."}), 403

    def block_task():
        all_ports_to_block_info = network_scanner.open_ports["TCP"] + network_scanner.open_ports["UDP"]
        
        if not all_ports_to_block_info:
            network_scanner.log("[*] No open ports detected to block.")
            return

        network_scanner.log(f"[*] Attempting to block {len(all_ports_to_block_info)} detected ports...")
        for p_info in all_ports_to_block_info:
            port = p_info['port']
            protocol = p_info['protocol']
            if port in network_scanner.whitelisted_ports:
                network_scanner.log(f"[~] Skipping whitelisted {protocol} port {port}.")
                continue
            
            success = network_scanner.block_port(port, protocol=protocol)
            if success and network_scanner.is_port_blocked(port, protocol=protocol):
                network_scanner.log(f"[✓] {protocol} Port {port} successfully blocked and verified.")
            else:
                network_scanner.log(f"[x] {protocol} Port {port} could not be verified as blocked. Manual check may be needed.")
        network_scanner.log("[+] Port blocking process completed.")

    threading.Thread(target=block_task).start()
    return jsonify({"status": "success", "message": "Port blocking initiated."})

@network_scanner_bp.route('/verify_ports', methods=['POST'])
def verify_ports_route():
    """
    API endpoint to verify if detected ports are closed.
    Runs the verification in a separate thread.
    """
    data = request.get_json()
    target_ip = data.get('target_ip')

    if not target_ip:
        target_ip = network_scanner.get_local_ip()
        if target_ip == "127.0.0.1" and not network_scanner.is_valid_ip_or_range(target_ip):
             network_scanner.log("[!] Cannot verify ports without a detected IP address or a target entered.")
             return jsonify({"status": "error", "message": "No target IP/range provided and local IP not detected for verification."}), 400

    def verify_task():
        network_scanner.verify_ports_closed(target_ip)
        network_scanner.log("[+] Port verification process completed.")

    threading.Thread(target=verify_task).start()
    return jsonify({"status": "success", "message": "Port verification initiated."})

@network_scanner_bp.route('/add_whitelist', methods=['POST'])
def add_whitelist_route():
    """API endpoint to add ports to the whitelist."""
    data = request.get_json()
    ports_str = data.get('ports')
    if network_scanner.add_to_whitelist(ports_str):
        return jsonify({"status": "success", "message": "Ports added to whitelist."})
    return jsonify({"status": "error", "message": "Failed to add ports to whitelist. Check log."}), 400

@network_scanner_bp.route('/clear_whitelist', methods=['POST']) # New endpoint for clearing whitelist
def clear_whitelist_route():
    """API endpoint to clear the whitelist."""
    network_scanner.clear_whitelist()
    return jsonify({"status": "success", "message": "Whitelist cleared."})

@network_scanner_bp.route('/whitelisted_ports', methods=['GET'])
def get_whitelisted_ports_route():
    """API endpoint to get the current list of whitelisted ports."""
    ports = network_scanner.get_whitelisted_ports()
    return jsonify({"whitelisted_ports": ports})

@network_scanner_bp.route('/get_scan_results', methods=['GET'])
def get_scan_results():
    """
    API endpoint to get the content of a specific scan result file.
    
    Query Parameters:
        type: The type of scan result to retrieve (tcp, tcp_syn, os, fragmented, aggressive)
    """
    scan_type = request.args.get('type', 'tcp')
    
    # Map scan types to their corresponding result files
    result_files = {
        'tcp': network_scanner.SCAN_RESULT_TCP,
        'tcp_syn': network_scanner.SCAN_RESULT_TCP_SYN,
        'os': network_scanner.SCAN_RESULT_OS,
        'fragmented': network_scanner.SCAN_RESULT_FRAGMENTED,
        'aggressive': network_scanner.SCAN_RESULT_AGGRESSIVE
    }
    
    # Get the file path for the requested scan type
    file_path = result_files.get(scan_type)
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({
            "status": "error",
            "message": f"No results available for {scan_type} scan."
        }), 404
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            return jsonify({
                "status": "success",
                "content": content,
                "scan_type": scan_type
            })
    except Exception as e:
        network_scanner.log(f"[!] Error reading {scan_type} scan results: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read {scan_type} scan results: {str(e)}"
        }), 500

@network_scanner_bp.route('/clear_log', methods=['POST'])
def clear_log_route():
    """API endpoint to clear the log file."""
    network_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "Log cleared."})

@network_scanner_bp.route('/log_stream')
def log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream log messages to the frontend.
    """
    def generate_logs():
        while True:
            # Check if there are messages in the queue
            if not network_scanner.log_queue.empty():
                message = network_scanner.log_queue.get()
                yield message
            else:
                # If no messages, sleep briefly to avoid busy-waiting
                time.sleep(0.1) # Small delay to prevent high CPU usage

    return Response(generate_logs(), mimetype='text/event-stream')
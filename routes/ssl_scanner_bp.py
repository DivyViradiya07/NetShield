from flask import Blueprint, render_template, jsonify, request, Response
import threading
import json
import time
import os

# Import the ssl_scanner module
from Services import ssl_scanner

ssl_scanner_bp = Blueprint('ssl_scanner_bp', __name__)

@ssl_scanner_bp.route('/')
def ssl_scanner_page():
    """Renders the SSL scanner page."""
    return render_template('ssl_scanner.html') # Ensure this template exists

@ssl_scanner_bp.route('/scan', methods=['POST'])
def scan_ssl():
    """
    API endpoint to initiate an SSL scan.
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_host = data.get('target_host')

    if not target_host:
        ssl_scanner.log("[!] Target host cannot be empty for SSL scan.")
        return jsonify({"status": "error", "message": "Target host is required."}), 400

    if not ssl_scanner.is_docker_available():
        ssl_scanner.log("[!] Docker is not available or not running. Cannot perform SSL scan.")
        return jsonify({"status": "error", "message": "Docker is not available or not running. Please check the log for details."}), 500
    
    if not ssl_scanner.ensure_sslscan_docker_image():
        ssl_scanner.log("[!] Failed to ensure SSLScan Docker image is available. Cannot perform SSL scan.")
        return jsonify({"status": "error", "message": "Failed to ensure SSLScan Docker image is available. Please check the log for details."}), 500

    # Function to run in a separate thread
    def scan_task():
        ssl_scanner.log(f"[*] Starting SSL scan for {target_host}...")
        report_file = ssl_scanner.run_ssl_scan(target_host)
        if report_file:
            # Optionally parse the report here and send a summary SSE event
            summary = ssl_scanner.parse_ssl_report(report_file)
            if summary:
                ssl_scanner.log(f"[+] SSL scan and report parsing complete for {target_host}.")
            else:
                ssl_scanner.log(f"[!] Failed to parse SSL report for {target_host}.")
        else:
            ssl_scanner.log(f"[!] SSL scan failed for {target_host}.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"SSL scan for {target_host} initiated."})

@ssl_scanner_bp.route('/report', methods=['GET'])
def get_ssl_report():
    """
    API endpoint to get the content of the SSL scan report file.
    """
    if not os.path.exists(ssl_scanner.SSL_REPORT_XML):
        return jsonify({
            "status": "error",
            "message": "No SSL scan report available. Please run a scan first."
        }), 404
    
    try:
        with open(ssl_scanner.SSL_REPORT_XML, 'r', encoding='utf-8') as f:
            content = f.read()
            return jsonify({
                "status": "success",
                "content": content,
                "report_file": os.path.basename(ssl_scanner.SSL_REPORT_XML)
            })
    except Exception as e:
        ssl_scanner.log(f"[!] Error reading SSL scan report: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to read SSL scan report: {str(e)}"
        }), 500

@ssl_scanner_bp.route('/clear_log', methods=['POST'])
def clear_ssl_log_route():
    """API endpoint to clear the SSL scanner log file."""
    ssl_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "SSL log cleared."})

@ssl_scanner_bp.route('/log_stream')
def ssl_log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream SSL scanner log messages to the frontend.
    """
    def generate_logs():
        while True:
            # Check if there are messages in the queue
            if not ssl_scanner.log_queue.empty():
                message = ssl_scanner.log_queue.get()
                yield message
            else:
                # If no messages, sleep briefly to avoid busy-waiting
                time.sleep(0.1) # Small delay to prevent high CPU usage

    return Response(generate_logs(), mimetype='text/event-stream')


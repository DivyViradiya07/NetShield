from flask import Blueprint, render_template, jsonify, request, Response
import threading
import json
import time
import os

# Assuming zap_scanner.py is in a 'Services' directory relative to where this blueprint is registered
# Or adjust the import path if your project structure is different
from Services import zap_scanner 

zap_scanner_bp = Blueprint('zap_scanner_bp', __name__)

# Route to render the ZAP scanner HTML page
@zap_scanner_bp.route('/')
def zap_scanner_page():
    """Renders the ZAP scanner page."""
    # Ensure you have a 'zap_scanner.html' template in your templates folder
    return render_template('zap_scanner.html')

@zap_scanner_bp.route('/scan', methods=['POST'])
def initiate_zap_scan():
    """
    API endpoint to initiate a ZAP scan (baseline, full, or api).
    Runs the scan in a separate thread to avoid blocking the Flask app.
    """
    data = request.get_json()
    target_url = data.get('target_url')
    scan_type = data.get('scan_type', 'baseline') # Default to 'baseline'
    api_definition = data.get('api_definition')
    api_format = data.get('api_format')

    if not target_url:
        zap_scanner.log("[!] Target URL is required for ZAP scan.")
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    valid_scan_types = ['baseline', 'full', 'api']
    if scan_type not in valid_scan_types:
        zap_scanner.log(f"[!] Invalid ZAP scan type: {scan_type}")
        return jsonify({"status": "error", "message": f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}"}), 400

    if scan_type == 'api' and (not api_definition or not api_format):
        zap_scanner.log("[!] API scan requires 'api_definition' (path or URL) and 'api_format'.")
        return jsonify({"status": "error", "message": "API scan requires 'api_definition' and 'api_format'."}), 400

    if not zap_scanner.is_docker_available():
        zap_scanner.log("[!] Docker is not available or not running. Cannot perform ZAP scan.")
        return jsonify({"status": "error", "message": "Docker is not available or not running. Please check the log for details."}), 500
    
    # Ensure ZAP Docker image is present before starting the scan thread
    # This call will also log its progress and potential failures
    zap_image_check_result = zap_scanner.ensure_zap_docker_image()
    if not zap_image_check_result:
        zap_scanner.log("[!] Failed to ensure ZAP Docker image is available. Cannot perform scan.")
        return jsonify({"status": "error", "message": "Failed to ensure ZAP Docker image is available. Please check the log for details."}), 500

    # Function to run in a separate thread
    def scan_task():
        zap_scanner.log(f"[*] Starting ZAP {scan_type.upper()} scan for {target_url}...")
        report_file = zap_scanner.run_zap_scan(target_url, scan_type, api_definition, api_format)
        if report_file:
            zap_scanner.log(f"[+] ZAP {scan_type.upper()} scan completed. Report saved to {report_file}")
            # Optionally parse and log summary immediately after scan completion
            summary = zap_scanner.parse_zap_report(report_file)
            if summary:
                zap_scanner.log(f"[+] ZAP {scan_type.upper()} scan summary: High={summary['High']}, Medium={summary['Medium']}, Low={summary['Low']}, Info={summary['Informational']}")
        else:
            zap_scanner.log(f"[!] ZAP {scan_type.upper()} scan failed.")

    threading.Thread(target=scan_task).start()
    return jsonify({"status": "success", "message": f"ZAP {scan_type.upper()} scan for {target_url} initiated."})

@zap_scanner_bp.route('/scan_results', methods=['GET'])
def get_zap_scan_results():
    """
    API endpoint to get the summary of a specific ZAP scan result.
    
    Query Parameters:
        type: The type of scan result to retrieve (baseline, full, api)
    """
    scan_type = request.args.get('type')
    
    if not scan_type:
        return jsonify({"status": "error", "message": "Scan type is required (baseline, full, or api)."}), 400

    # Map scan types to their corresponding result files
    result_files = {
        'baseline': zap_scanner.ZAP_REPORT_BASELINE,
        'full': zap_scanner.ZAP_REPORT_FULL,
        'api': zap_scanner.ZAP_REPORT_API
    }
    
    file_path = result_files.get(scan_type)
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({
            "status": "error",
            "message": f"No JSON report available for {scan_type} scan. Please run the scan first."
        }), 404
    
    summary = zap_scanner.parse_zap_report(file_path)
    if summary:
        return jsonify({
            "status": "success",
            "scan_type": scan_type,
            "summary": summary
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"Failed to parse {scan_type} report. Check ZAP logs for details."
        }), 500

@zap_scanner_bp.route('/clear_log', methods=['POST'])
def clear_zap_log_route():
    """API endpoint to clear the ZAP scanner log file."""
    zap_scanner.clear_log_file()
    return jsonify({"status": "success", "message": "ZAP log cleared."})

@zap_scanner_bp.route('/log_stream')
def zap_log_stream():
    """
    Server-Sent Events (SSE) endpoint to stream ZAP scanner log messages to the frontend.
    """
    def generate_logs():
        while True:
            # Check if there are messages in the queue
            if not zap_scanner.log_queue.empty():
                message = zap_scanner.log_queue.get()
                yield message
            else:
                # If no messages, sleep briefly to avoid busy-waiting
                time.sleep(0.1) # Small delay to prevent high CPU usage

    return Response(generate_logs(), mimetype='text/event-stream')

import subprocess
import os
import sys
import ctypes
from datetime import datetime
import platform
import queue
import time
import json
import shutil # Added for shutil.copy

# Define paths for storing results
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results", "zap_scanner")
ZAP_REPORT_BASELINE = os.path.join(RESULTS_DIR, "zap_baseline_report.json")
ZAP_REPORT_FULL = os.path.join(RESULTS_DIR, "zap_full_report.json")
ZAP_REPORT_API = os.path.join(RESULTS_DIR, "zap_api_report.json")
# Define log file path in the root directory
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs' ,"zap_agent_log.txt")

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# Global queue for logging messages to be consumed by Flask (or similar)
log_queue = queue.Queue()

def log(message):
    """
    Logs messages to an in-memory queue and to a file.
    This log function is designed to be consumed by a web application.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"data: [{timestamp}] {message}\n\n" # SSE format
    
    # Put message into the queue for a web app to stream
    log_queue.put(full_message)

    # Also write to a file for persistent logging
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        # Log to console if file write fails, as this is a critical logging function
        print(f"ERROR: Failed to write to {LOG_FILE}: {e}")

def send_sse_event(event_name, data=""):
    """Sends a custom SSE event to the frontend."""
    # Ensure data is a JSON string if it's an object/list
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    else:
        data_str = str(data) # Convert other types to string

    sse_message = f"event: {event_name}\ndata: {data_str}\n\n"
    log_queue.put(sse_message)

def _get_subprocess_creation_flags():
    """Returns appropriate creation flags for subprocess based on OS."""
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0 # Default for Linux/macOS

def is_admin():
    """Checks if the script is running with administrative/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserIsAdmin()
        except Exception as e:
            log(f"[!] Error checking admin privileges (Windows): {e}")
            return False
    else: # Linux/macOS
        return os.geteuid() == 0

def elevate_if_needed():
    """
    Checks for administrative/root privileges. For Docker, this usually means
    the Docker daemon is running with appropriate permissions, or the user
    running this script is part of the 'docker' group.
    """
    if not is_admin():
        msg = "Running Docker commands might require elevated privileges or being part of the 'docker' group."
        log(f"[!] Privilege Note: {msg}")
        return False
    return True

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

def ensure_zap_docker_image():
    """
    Checks if the OWASP ZAP Docker image (stable) from GHCR is present. If not, attempts to pull it.
    Returns the name of the successfully pulled/found image (str) on success, None otherwise.
    """
    ghcr_image = "ghcr.io/zaproxy/zaproxy:stable"
    
    log(f"[*] Checking for Docker image: {ghcr_image}...")
    try:
        # Check if GHCR image exists locally
        result = subprocess.run(['docker', 'images', '-q', ghcr_image], capture_output=True, text=True, check=False, creationflags=_get_subprocess_creation_flags())
        if result.stdout.strip():
            log(f"[✓] Docker image {ghcr_image} is already present locally.")
            return ghcr_image
        else:
            # Attempt to pull GHCR image
            log(f"[*] Docker image {ghcr_image} not found locally. Attempting to pull...")
            pull_result = subprocess.run(['docker', 'pull', ghcr_image], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
            log(f"[+] Successfully pulled Docker image: {ghcr_image}")
            return ghcr_image
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to pull Docker image {ghcr_image}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        log("[!] Docker image pull failed. Please ensure your Docker daemon is running and has internet access, and that you have appropriate permissions.")
        return None
    except FileNotFoundError:
        log("[!] Docker command not found. Cannot check or pull Docker image. Please ensure Docker Desktop/Engine is installed and in your PATH.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during Docker image management: {e}")
        return None

def run_zap_scan(target_url, scan_type="baseline", api_definition=None, api_format=None):
    """
    Runs an OWASP ZAP scan using Docker.
    
    Args:
        target_url (str): The URL of the web application to scan.
        scan_type (str): Type of ZAP scan ('baseline', 'full', 'api').
        api_definition (str, optional): Path or URL to API definition file (for 'api' scan).
        api_format (str, optional): Format of API definition ('openapi', 'soap', 'graphql').
    
    Returns:
        str: Path to the generated report file on success, None otherwise.
    """
    if not target_url:
        log("[!] Target URL cannot be empty for ZAP scan.")
        return None

    log(f"[+] Running ZAP {scan_type} scan on {target_url}...")

    # Ensure Docker is available and the ZAP image is present
    zap_image_name = ensure_zap_docker_image()
    if not zap_image_name:
        log("[!] ZAP Docker image could not be found or pulled. Cannot proceed with scan.")
        return None

    # Define output file path for the report
    output_report_file = None
    if scan_type == "baseline":
        output_report_file = ZAP_REPORT_BASELINE
    elif scan_type == "full":
        output_report_file = ZAP_REPORT_FULL
    elif scan_type == "api":
        output_report_file = ZAP_REPORT_API
    else:
        log(f"[!] Unknown ZAP scan type: {scan_type}. Supported types: 'baseline', 'full', 'api'.")
        return None
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_report_file), exist_ok=True)

    # Construct the Docker command
    docker_cmd_base = [
        'docker', 'run', '--rm',
        '-v', f"{RESULTS_DIR}:/zap/wrk:rw", # Mount results directory for output
        zap_image_name # Use the dynamically determined image name
    ]

    zap_command = []
    if scan_type == "baseline":
        # Baseline scan: Passive scan for a given URL
        zap_command = [
            'zap-baseline.py',
            '-t', target_url,
            '-I', # Do not return failure on warning (changed from -W)
            # Pass only the basename of the report files, ZAP will write them to /zap/wrk
            '-r', os.path.basename(output_report_file).replace(".json", ".html"), # HTML report
            '-J', os.path.basename(output_report_file) # JSON report
        ]
        log(f"[*] ZAP Baseline scan will generate HTML and JSON reports.")
    elif scan_type == "full":
        # Full scan: Crawl + Active scan
        zap_command = [
            'zap-full-scan.py',
            '-t', target_url,
            '-I', # Do not return failure on warning (changed from -W)
            # Pass only the basename of the report files, ZAP will write them to /zap/wrk
            '-r', os.path.basename(output_report_file).replace(".json", ".html"), # HTML report
            '-J', os.path.basename(output_report_file), # JSON report
            # Removed '-p 5000' as it was causing FileNotFoundError
        ]
        log(f"[*] ZAP Full scan will generate HTML and JSON reports.")
    elif scan_type == "api":
        if not api_definition or not api_format:
            log("[!] API scan requires 'api_definition' and 'api_format' arguments.")
            return None
        
        # API scan: Import API definition and then scan
        # Note: For API scan, you might need to copy the definition file into the container
        # or expose it via a URL accessible from within the container.
        # For simplicity, assuming api_definition is a local path that needs to be mounted.
        # This example assumes the API definition is copied to the mounted volume.
        
        # Example: If api_definition is a local file, it needs to be accessible in /zap/wrk
        # If it's a URL, ZAP can fetch it directly.
        
        # Assuming api_definition is a path relative to the host's RESULTS_DIR
        # Or a URL that ZAP can directly access
        api_def_path_in_container = f'/zap/wrk/{os.path.basename(api_definition)}' if os.path.exists(api_definition) else api_definition

        zap_command = [
            'zap-api-scan.py',
            '-t', api_def_path_in_container, # Target is the API definition
            '-f', api_format, # Format of the API definition
            '-I', # Do not return failure on warning (changed from -W)
            '-r', os.path.basename(output_report_file).replace(".json", ".html"),
            '-J', os.path.basename(output_report_file),
            '-d' # Debug output
        ]
        # If api_definition is a local file, copy it to RESULTS_DIR first so it's mounted
        if os.path.exists(api_definition) and os.path.abspath(api_definition) != os.path.abspath(os.path.join(RESULTS_DIR, os.path.basename(api_definition))):
            try:
                shutil.copy(api_definition, RESULTS_DIR)
                log(f"[*] Copied API definition '{api_definition}' to '{RESULTS_DIR}' for mounting.")
            except Exception as e:
                log(f"[!] Failed to copy API definition file: {e}")
                return None
        log(f"[*] ZAP API scan will generate HTML and JSON reports.")

    full_docker_cmd = docker_cmd_base + zap_command

    try:
        log(f"[*] Executing ZAP Docker command: {' '.join(full_docker_cmd)}")
        # Run the Docker container
        process = subprocess.run(
            full_docker_cmd,
            capture_output=True,
            text=True,
            check=False, # Do not raise exception for non-zero exit codes immediately
            creationflags=_get_subprocess_creation_flags()
        )
        
        # Log stdout and stderr
        if process.stdout:
            log(f"[ZAP STDOUT]\n{process.stdout}")
        if process.stderr:
            log(f"[ZAP STDERR]\n{process.stderr}")

        # ZAP's packaged scans return non-zero exit codes for warnings/failures by default.
        # We're using -I to treat warnings as info, so a non-zero exit code here
        # still indicates a more serious issue (e.g., scan script internal error, target unreachable).
        if process.returncode != 0:
            log(f"[!] ZAP {scan_type} scan failed with exit code {process.returncode}. This usually indicates a problem with the scan setup or target, not just warnings.")
            log(f"[!] Check ZAP logs above for details.")
            return None
        
        log(f"[+] ZAP {scan_type} scan complete. Reports saved to {output_report_file.replace('.json', '.html')} and {output_report_file}")
        send_sse_event("zap_scan_complete", {"scan_type": scan_type, "target_url": target_url, "report_file": output_report_file})
        return output_report_file
        
    except FileNotFoundError:
        log("[!] Docker command not found. Please ensure Docker is installed and running.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during ZAP {scan_type} scan: {e}")
        return None

def parse_zap_report(report_file):
    """
    Parses a ZAP JSON report file and returns a summary of alerts.
    
    Args:
        report_file (str): Path to the ZAP JSON report file.
        
    Returns:
        dict: A dictionary containing a summary of alerts, or None if parsing fails.
    """
    if not os.path.exists(report_file):
        log(f"[!] ZAP report file not found: {report_file}")
        return None
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        alerts_summary = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
            "Total": 0,
            "Details": []
        }
        
        if "site" in report_data and len(report_data["site"]) > 0:
            for site_entry in report_data["site"]:
                if "alerts" in site_entry:
                    for alert in site_entry["alerts"]:
                        risk = alert.get("riskdesc", "Informational").split(' ')[0] # e.g., "High (Medium)" -> "High"
                        alerts_summary[risk] = alerts_summary.get(risk, 0) + 1
                        alerts_summary["Total"] += 1
                        
                        alerts_summary["Details"].append({
                            "name": alert.get("alert", "N/A"),
                            "risk": risk,
                            "confidence": alert.get("confidence", "N/A"),
                            "url": alert.get("url", "N/A"),
                            "description": alert.get("description", "N/A")
                        })
        
        log(f"[+] ZAP report '{os.path.basename(report_file)}' parsed successfully.")
        send_sse_event("zap_report_parsed", alerts_summary)
        return alerts_summary

    except json.JSONDecodeError as e:
        log(f"[!] Error decoding ZAP JSON report '{report_file}': {e}")
        return None
    except Exception as e:
        log(f"[!] Unexpected error parsing ZAP report '{report_file}': {e}")
        return None

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] ZAP log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing ZAP log file: {e}")

# Initialization check
if not elevate_if_needed():
    log("[!] Application might not function correctly due to insufficient Docker permissions.")


if __name__ == "__main__":
    log("Starting ZAP Scanner demonstration...")
    clear_log_file() # Clear previous logs

    # --- Example 1: Baseline Scan ---
    target_web_app_url = "http://juice-shop.herokuapp.com" # Example vulnerable web app
    log(f"Attempting ZAP Baseline Scan on: {target_web_app_url}")
    baseline_report_path = run_zap_scan(target_web_app_url, scan_type="baseline")
    
    if baseline_report_path:
        log(f"ZAP Baseline Scan completed. Parsing report: {baseline_report_path}")
        baseline_summary = parse_zap_report(baseline_report_path)
        if baseline_summary:
            print("\n--- ZAP Baseline Scan Summary ---")
            for risk, count in baseline_summary.items():
                if risk != "Details":
                    print(f"{risk}: {count}")
            # print("\nDetails:")
            # for detail in baseline_summary["Details"]:
            #     print(f"  - {detail['name']} ({detail['risk']}) - {detail['url']}")
        else:
            log("[!] Failed to parse baseline report.")
    else:
        log("[!] ZAP Baseline Scan failed.")

    print("\n" + "="*50 + "\n")
    time.sleep(5) # Give some time before the next scan

    # --- Example 2: Full Scan ---
    log(f"Attempting ZAP Full Scan on: {target_web_app_url}")
    full_report_path = run_zap_scan(target_web_app_url, scan_type="full")

    if full_report_path:
        log(f"ZAP Full Scan completed. Parsing report: {full_report_path}")
        full_summary = parse_zap_report(full_report_path)
        if full_summary:
            print("\n--- ZAP Full Scan Summary ---")
            for risk, count in full_summary.items():
                if risk != "Details":
                    print(f"{risk}: {count}")
            # print("\nDetails:")
            # for detail in full_summary["Details"]:
            #     print(f"  - {detail['name']} ({detail['risk']}) - {detail['url']}")
        else:
            log("[!] Failed to parse full report.")
    else:
        log("[!] ZAP Full Scan failed.")

    print("\n" + "="*50 + "\n")
    time.sleep(5) # Give some time before the next scan

    # --- Example 3: API Scan (requires an API definition file) ---
    # For this example, you would need a local OpenAPI/Swagger file, e.g., 'openapi.json'
    # api_def_file = "path/to/your/openapi.json" 
    # if os.path.exists(api_def_file):
    #     log(f"Attempting ZAP API Scan with definition: {api_def_file}")
    #     api_report_path = run_zap_scan(target_web_app_url, scan_type="api", api_definition=api_def_file, api_format="openapi")
    #     if api_report_path:
    #         log(f"ZAP API Scan completed. Parsing report: {api_report_path}")
    #         api_summary = parse_zap_report(api_report_path)
    #         if api_summary:
    #             print("\n--- ZAP API Scan Summary ---")
    #             for risk, count in api_summary.items():
    #                 if risk != "Details":
    #                     print(f"{risk}: {count}")
    #         else:
    #             log("[!] Failed to parse API report.")
    #     else:
    #         log("[!] ZAP API Scan failed.")
    # else:
    #     log(f"[!] Skipping API scan: API definition file '{api_def_file}' not found.")

    log("ZAP Scanner demonstration finished.")
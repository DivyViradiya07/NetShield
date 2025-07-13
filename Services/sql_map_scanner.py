import subprocess
import os
import sys
import ctypes
from datetime import datetime
import platform
import queue
import time
import json
import re # For parsing sqlmap text output
import shutil # For copying files if needed

# Define paths for storing results
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results", "sql_scanner")
# sqlmap will create a directory per target directly within SQLMAP_OUTPUT_DIR
SQLMAP_OUTPUT_DIR = os.path.join(RESULTS_DIR, "sqlmap_output") 
# Define log file path in the root directory
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs' ,"sql_agent_log.txt")

# Ensure results directories exist
os.makedirs(SQLMAP_OUTPUT_DIR, exist_ok=True)

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
    Checks for administrative/root privileges.
    Note: Running sqlmap might require network access that is sometimes restricted
    without elevated privileges, depending on system configuration.
    """
    if not is_admin():
        msg = "Running sqlmap might require elevated privileges for full network access or certain operations."
        log(f"[!] Privilege Note: {msg}")
        return False
    return True

# No longer needed as we are not using Docker
# def is_docker_available():
#     """Checks if Docker is installed and accessible on the system."""
#     try:
#         subprocess.check_output(['docker', 'info'], text=True, stderr=subprocess.PIPE, creationflags=_get_subprocess_creation_flags())
#         return True
#     except subprocess.CalledProcessError as e:
#         log(f"[!] Docker daemon not running or not accessible: {e.stderr.strip() if e.stderr else 'No stderr output'}")
#         return False
#     except FileNotFoundError:
#         log("[!] Docker command not found. Please ensure Docker Desktop/Engine is installed and in your PATH.")
#         return False
#     except Exception as e:
#         log(f"[!] An unexpected error occurred while checking Docker: {e}")
#         return False

# No longer needed as we are not using Docker
# def ensure_sqlmap_docker_image():
#     """
#     Checks if the m4n3dw0lf/sqlmap Docker image is present. If not, attempts to pull it.
#     Returns the name of the successfully pulled/found image (str) on success, None otherwise.
#     """
#     docker_image = "m4n3dw0lf/sqlmap"
    
#     log(f"[*] Checking for Docker image: {docker_image}...")
#     try:
#         # Check if Docker image exists locally
#         result = subprocess.run(['docker', 'images', '-q', docker_image], capture_output=True, text=True, check=False, creationflags=_get_subprocess_creation_flags())
#         if result.stdout.strip():
#             log(f"[✓] Docker image {docker_image} is already present locally.")
#             return docker_image
#         else:
#             # Attempt to pull Docker image
#             log(f"[*] Docker image {docker_image} not found locally. Attempting to pull...")
#             pull_result = subprocess.run(['docker', 'pull', docker_image], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
#             log(f"[+] Successfully pulled Docker image: {docker_image}")
#             return docker_image
#     except subprocess.CalledProcessError as e:
#         log(f"[!] Failed to pull Docker image {docker_image}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
#         log("[!] Docker image pull failed. Please ensure your Docker daemon is running and has internet access, and that you have appropriate permissions.")
#         return None
#     except FileNotFoundError:
#         log("[!] Docker command not found. Cannot check or pull Docker image. Please ensure Docker Desktop/Engine is installed and in your PATH.")
#         return None
#     except Exception as e:
#         log(f"[!] An unexpected error occurred during Docker image management: {e}")
#         return None

def run_sql_scan(target_url, scan_level=1, scan_risk=1, data=None, headers=None, cookies=None, user_agent=None, referer=None):
    """
    Runs an SQL injection scan using a locally installed sqlmap.
    
    Args:
        target_url (str): The URL to scan for SQL injection.
        scan_level (int): Level of tests to perform (1-5, default 1).
        scan_risk (int): Risk of tests to perform (1-3, default 1).
        data (str, optional): Data to be sent in POST request.
        headers (str, optional): Extra headers to inject.
        cookies (str, optional): HTTP cookies.
        user_agent (str, optional): HTTP User-Agent header.
        referer (str, optional): HTTP Referer header.
    
    Returns:
        str: Path to the sqlmap output directory on success, None otherwise.
    """
    if not target_url:
        log("[!] Target URL cannot be empty for SQL scan.")
        return None

    log(f"[+] Running SQL scan on {target_url} (Level: {scan_level}, Risk: {scan_risk})...")

    # Path to the sqlmap.py script, assuming it's cloned into a 'sqlmap-dev' folder
    # sibling to this script's directory (i.e., inside 'Services').
    sqlmap_script_path = os.path.join(os.path.dirname(__file__), 'sqlmap-dev', 'sqlmap.py')
    
    if not os.path.exists(sqlmap_script_path):
        log(f"[!] sqlmap.py not found at '{sqlmap_script_path}'.")
        log("[!] Please ensure the sqlmap repository is cloned into a 'sqlmap-dev' directory inside the 'Services' folder.")
        log("[!] Example: git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git Services/sqlmap-dev")
        return None
    
    # Ensure the output directory exists
    os.makedirs(SQLMAP_OUTPUT_DIR, exist_ok=True)

    sqlmap_cmd_base = [
        sys.executable, # Use the current Python interpreter (from the virtual environment)
        sqlmap_script_path,
        '-u', target_url,
        '--batch', # Never ask for user input
        '--random-agent', # Use a random User-Agent
        '--forms', # Parse forms on target URLs
        '--crawl=1', # Crawl the target up to 1 level deep
        f'--output-dir={SQLMAP_OUTPUT_DIR}', # Specify output directory directly on host
        f'--level={scan_level}',
        f'--risk={scan_risk}'
    ]

    # Add optional parameters if provided
    if data:
        sqlmap_cmd_base.extend(['--data', data])
    if headers:
        sqlmap_cmd_base.extend(['--headers', headers])
    if cookies:
        sqlmap_cmd_base.extend(['--cookie', cookies])
    if user_agent:
        sqlmap_cmd_base.extend(['--user-agent', user_agent])
    if referer:
        sqlmap_cmd_base.extend(['--referer', referer])

    try:
        log(f"[*] Executing SQLMap command: {' '.join(sqlmap_cmd_base)}")
        process = subprocess.run(
            sqlmap_cmd_base,
            capture_output=True,
            text=True,
            check=False, # sqlmap can return non-zero for found vulnerabilities
            creationflags=_get_subprocess_creation_flags()
        )
        
        # Log stdout and stderr
        if process.stdout:
            log(f"[SQLMap STDOUT]\n{process.stdout}")
        if process.stderr:
            log(f"[SQLMap STDERR]\n{process.stderr}")

        # sqlmap's exit codes: 0 (no vulnerabilities found), 1 (vulnerabilities found), 2 (error)
        if process.returncode == 2:
            log(f"[!] SQL scan failed with exit code {process.returncode}. This indicates an error during the scan.")
            log(f"[!] Check SQLMap logs above for details.")
            return None
        elif process.returncode == 1:
            log(f"[+] SQL scan completed. Vulnerabilities found!")
        else:
            log(f"[+] SQL scan completed. No vulnerabilities found.")
        
        # Determine the actual output directory created by sqlmap
        # sqlmap creates a directory like 'target.com' or 'target_ip'
        # We need to find the most recently modified directory in SQLMAP_OUTPUT_DIR
        latest_output_dir = None
        # Sanitize target_url to match sqlmap's directory naming convention
        # sqlmap uses a hash of the URL, but often a simplified domain/IP for the top-level folder
        # We'll look for directories created recently to find the correct one.
        
        subdirs = [os.path.join(SQLMAP_OUTPUT_DIR, d) for d in os.listdir(SQLMAP_OUTPUT_DIR) if os.path.isdir(os.path.join(SQLMAP_OUTPUT_DIR, d))]
        if subdirs:
            latest_output_dir = max(subdirs, key=os.path.getmtime)

        if latest_output_dir and os.path.exists(latest_output_dir):
            log(f"[+] SQLMap output saved to: {latest_output_dir}")
            send_sse_event("sql_scan_complete", {"target_url": target_url, "output_dir": latest_output_dir, "return_code": process.returncode})
            return latest_output_dir
        else:
            log(f"[!] SQL scan completed, but no output directory found for {target_url}.")
            log("[!] This might happen if the target is unreachable or sqlmap encountered an early error.")
            return None
        
    except FileNotFoundError:
        log("[!] Python interpreter or sqlmap.py script not found. Ensure Python is in PATH and sqlmap is correctly cloned.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during SQL scan: {e}")
        return None

def parse_sql_report(output_dir):
    """
    Parses sqlmap's text-based output files and returns a structured summary.
    
    Args:
        output_dir (str): Path to the sqlmap output directory for a specific target.
        
    Returns:
        dict: A dictionary containing a summary of SQL injection findings, or None if parsing fails.
    """
    if not output_dir or not os.path.exists(output_dir):
        log(f"[!] SQLMap output directory not found: {output_dir}")
        return None
    
    scan_summary = {
        "vulnerable_parameters": [],
        "database_management_system": "N/A",
        "web_server": "N/A",
        "operating_system": "N/A",
        "detected_payloads": [],
        "errors": []
    }

    # Common sqlmap output files to check
    # sqlmap creates a log file (e.g., log) and a text file (e.g., target.txt)
    # The main log file is usually named 'log' within the target's output directory
    main_log_file = os.path.join(output_dir, "log")
    
    if not os.path.exists(main_log_file):
        # Fallback: sometimes the main output is directly in a .txt file named after the target
        # Let's try to find any .txt file in the directory
        txt_files = [f for f in os.listdir(output_dir) if f.endswith('.txt')]
        if txt_files:
            main_log_file = os.path.join(output_dir, txt_files[0])
        else:
            log(f"[!] Main sqlmap log file 'log' or any .txt file not found in {output_dir}.")
            return scan_summary # Return empty summary if no log file

    try:
        with open(main_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

            # Regex patterns to extract information
            # Vulnerable parameters
            vulnerable_param_pattern = re.compile(r"parameter '(.+?)' is vulnerable\.")
            scan_summary["vulnerable_parameters"] = list(set(vulnerable_param_pattern.findall(content))) # Use set to avoid duplicates

            # DBMS
            dbms_pattern = re.compile(r"back-end DBMS: (.+?)\n")
            dbms_match = dbms_pattern.search(content)
            if dbms_match:
                scan_summary["database_management_system"] = dbms_match.group(1).strip()

            # Web Server
            web_server_pattern = re.compile(r"web server: (.+?)\n")
            web_server_match = web_server_pattern.search(content)
            if web_server_match:
                scan_summary["web_server"] = web_server_match.group(1).strip()

            # Operating System
            os_pattern = re.compile(r"operating system: (.+?)\n")
            os_match = os_pattern.search(content)
            if os_match:
                scan_summary["operating_system"] = os_match.group(1).strip()
            
            # Detected Payloads (often indicated by '[PAYLOAD]' or similar markers)
            payload_pattern = re.compile(r"\[PAYLOAD\]: (.+?)\n")
            scan_summary["detected_payloads"] = list(set(payload_pattern.findall(content)))

            # Errors/Warnings (simple check for common error indicators)
            error_pattern = re.compile(r"\[CRITICAL\]|\[ERROR\]|\[WARNING\]", re.IGNORECASE)
            errors_found = error_pattern.findall(content)
            if errors_found:
                # Extract lines containing errors/warnings for more context
                error_lines = [line.strip() for line in content.splitlines() if error_pattern.search(line)]
                scan_summary["errors"] = list(set(error_lines)) # Remove duplicates

        log(f"[+] SQLMap report from '{output_dir}' parsed successfully.")
        send_sse_event("sql_report_parsed", scan_summary)
        return scan_summary

    except Exception as e:
        log(f"[!] Unexpected error parsing SQLMap report from '{output_dir}': {e}")
        return None

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] SQL log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing SQL log file: {e}")

def get_latest_sqlmap_report_content():
    """
    Retrieves the content of the latest sqlmap log file.
    """
    latest_output_dir = None
    subdirs = [os.path.join(SQLMAP_OUTPUT_DIR, d) for d in os.listdir(SQLMAP_OUTPUT_DIR) if os.path.isdir(os.path.join(SQLMAP_OUTPUT_DIR, d))]
    if subdirs:
        latest_output_dir = max(subdirs, key=os.path.getmtime)

    if latest_output_dir:
        main_log_file = os.path.join(latest_output_dir, "log")
        if not os.path.exists(main_log_file):
            txt_files = [f for f in os.listdir(latest_output_dir) if f.endswith('.txt')]
            if txt_files:
                main_log_file = os.path.join(latest_output_dir, txt_files[0])
            else:
                return "No main log or .txt file found in the latest sqlmap output directory."
        
        try:
            with open(main_log_file, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Error reading latest sqlmap report: {e}"
    return "No sqlmap scan reports found."


# Initialization check
if not elevate_if_needed():
    log("[!] Application might not function correctly due to insufficient privileges.")

if __name__ == "__main__":
    log("Starting SQL Scanner demonstration...")
    clear_log_file() # Clear previous logs

    # --- IMPORTANT SETUP INSTRUCTION ---
    log("[*] Ensure sqlmap is cloned into the 'Services/sqlmap-dev' directory:")
    log("[*] git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git Services/sqlmap-dev")
    log("[*] Also ensure you have installed sqlmap's dependencies (e.g., pip install -r Services/sqlmap-dev/requirements.txt)")
    # --- END IMPORTANT SETUP INSTRUCTION ---

    # Example: Scan a known vulnerable target
    # NOTE: Replace with a safe, legitimate target for testing.
    # DO NOT scan targets you do not have explicit permission to scan.
    target = "http://testphp.vulnweb.com/listproducts.php?cat=1" 
    log(f"Attempting SQL Scan on: {target}")
    output_dir = run_sql_scan(target, scan_level=3, scan_risk=2)
    
    if output_dir:
        log(f"SQL Scan completed. Parsing report from: {output_dir}")
        summary = parse_sql_report(output_dir)
        if summary:
            print("\n--- SQL Scan Summary ---")
            print(f"Target: {target}")
            print(f"DBMS: {summary.get('database_management_system')}")
            print(f"Web Server: {summary.get('web_server')}")
            print(f"OS: {summary.get('operating_system')}")
            print("\nVulnerable Parameters:")
            if summary['vulnerable_parameters']:
                for param in summary['vulnerable_parameters']:
                    print(f"  - {param}")
            else:
                print("  No vulnerable parameters found.")
            
            print("\nDetected Payloads:")
            if summary['detected_payloads']:
                for payload in summary['detected_payloads']:
                    print(f"  - {payload}")
            else:
                print("  No specific payloads detected.")

            print("\nErrors/Warnings from Scan:")
            if summary['errors']:
                for error in summary['errors']:
                    print(f"  - {error}")
            else:
                print("  No significant errors or warnings.")
        else:
            log("[!] Failed to parse SQL report.")
    else:
        log("[!] SQL Scan failed.")

    log("SQL Scanner demonstration finished.")

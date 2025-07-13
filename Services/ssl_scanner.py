import subprocess
import os
import sys
import ctypes
from datetime import datetime
import platform
import queue
import time
import json
import xml.etree.ElementTree as ET # For parsing XML output

# Define paths for storing results
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results", "ssl_scanner")
SSL_REPORT_XML = os.path.join(RESULTS_DIR, "ssl_report.xml")
# Define log file path in the root directory
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs' ,"ssl_agent_log.txt")

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

def ensure_sslscan_docker_image():
    """
    Checks if the shamelesscookie/sslscan Docker image is present. If not, attempts to pull it.
    Returns the name of the successfully pulled/found image (str) on success, None otherwise.
    """
    docker_image = "shamelesscookie/sslscan"
    
    log(f"[*] Checking for Docker image: {docker_image}...")
    try:
        # Check if Docker image exists locally
        result = subprocess.run(['docker', 'images', '-q', docker_image], capture_output=True, text=True, check=False, creationflags=_get_subprocess_creation_flags())
        if result.stdout.strip():
            log(f"[✓] Docker image {docker_image} is already present locally.")
            return docker_image
        else:
            # Attempt to pull Docker image
            log(f"[*] Docker image {docker_image} not found locally. Attempting to pull...")
            pull_result = subprocess.run(['docker', 'pull', docker_image], capture_output=True, text=True, check=True, creationflags=_get_subprocess_creation_flags())
            log(f"[+] Successfully pulled Docker image: {docker_image}")
            return docker_image
    except subprocess.CalledProcessError as e:
        log(f"[!] Failed to pull Docker image {docker_image}: {e.stderr.strip() if e.stderr else 'No detailed error.'}")
        log("[!] Docker image pull failed. Please ensure your Docker daemon is running and has internet access, and that you have appropriate permissions.")
        return None
    except FileNotFoundError:
        log("[!] Docker command not found. Cannot check or pull Docker image. Please ensure Docker Desktop/Engine is installed and in your PATH.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during Docker image management: {e}")
        return None

def run_ssl_scan(target_host):
    """
    Runs an SSL/TLS scan using the shamelesscookie/sslscan Docker image.
    Outputs the report to an XML file.
    
    Args:
        target_host (str): The target host (IP or domain) to scan.
    
    Returns:
        str: Path to the generated XML report file on success, None otherwise.
    """
    if not target_host:
        log("[!] Target host cannot be empty for SSL scan.")
        return None

    log(f"[+] Running SSL scan on {target_host}...")

    # Ensure Docker is available and the sslscan image is present
    sslscan_image_name = ensure_sslscan_docker_image()
    if not sslscan_image_name:
        log("[!] SSLScan Docker image could not be found or pulled. Cannot proceed with scan.")
        return None
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(SSL_REPORT_XML), exist_ok=True)

    # Construct the Docker command to run sslscan and output XML to a mounted volume
    # We need to ensure the XML file is written to /tmp/report.xml inside the container
    # and then that file is mapped to SSL_REPORT_XML on the host.
    docker_cmd = [
        'docker', 'run', '--rm',
        '-v', f"{RESULTS_DIR}:/tmp:rw", # Mount results directory to /tmp inside container
        sslscan_image_name,
        '--xml=/tmp/ssl_report.xml', # Output XML to a file in the mounted /tmp directory
        '--show-client-cas', # Add flag to show client CAs
        '--show-cipher-ids', # Add flag to show cipher IDs
        target_host
    ]

    try:
        log(f"[*] Executing SSLScan Docker command: {' '.join(docker_cmd)}")
        process = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            check=False, # Do not raise exception for non-zero exit codes immediately
            creationflags=_get_subprocess_creation_flags()
        )
        
        # Log stdout and stderr
        if process.stdout:
            log(f"[SSLScan STDOUT]\n{process.stdout}")
        if process.stderr:
            log(f"[SSLScan STDERR]\n{process.stderr}")

        if process.returncode != 0:
            log(f"[!] SSL scan failed with exit code {process.returncode}.")
            log(f"[!] Check SSLScan logs above for details.")
            return None
        
        # Verify if the XML report file was created
        if os.path.exists(SSL_REPORT_XML) and os.path.getsize(SSL_REPORT_XML) > 0:
            log(f"[+] SSL scan complete. Report saved to {SSL_REPORT_XML}")
            send_sse_event("ssl_scan_complete", {"target_host": target_host, "report_file": SSL_REPORT_XML})
            return SSL_REPORT_XML
        else:
            log(f"[!] SSL scan completed, but no XML report file was generated or it's empty: {SSL_REPORT_XML}")
            return None
        
    except FileNotFoundError:
        log("[!] Docker command not found. Please ensure Docker is installed and running.")
        return None
    except Exception as e:
        log(f"[!] An unexpected error occurred during SSL scan: {e}")
        return None

def parse_ssl_report(report_file):
    """
    Parses an SSLScan XML report file and returns a structured summary.
    
    Args:
        report_file (str): Path to the SSLScan XML report file.
        
    Returns:
        dict: A dictionary containing a summary of SSL/TLS details, or None if parsing fails.
    """
    if not os.path.exists(report_file):
        log(f"[!] SSLScan report file not found: {report_file}")
        return None
    
    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        scan_summary = {
            "target": "N/A",
            "ip": "N/A",
            "port": "N/A",
            "protocols": [],
            "ciphers": [],
            "certificate": {},
            "client_cas": [], # Added for client CAs
            "vulnerabilities": []
        }

        # Extract target info from the <ssltest> element
        ssltest_elem = root.find('ssltest')
        if ssltest_elem is not None:
            scan_summary["target"] = ssltest_elem.get('host', 'N/A')
            # IP is not directly in the <ssltest> tag attributes in the provided XML
            # If it appears elsewhere, we'd need to adjust.
            scan_summary["port"] = ssltest_elem.get('port', 'N/A')
        
        # Protocols
        for protocol_elem in root.findall('.//protocol'):
            scan_summary["protocols"].append({
                "name": protocol_elem.get('version', 'N/A'), # 'version' attribute is the protocol name
                "type": protocol_elem.get('type', 'N/A'),
                "enabled": protocol_elem.get('enabled', 'N/A'),
                "notes": protocol_elem.get('notes', 'N/A')
            })

        # Ciphers
        for cipher_elem in root.findall('.//cipher'):
            scan_summary["ciphers"].append({
                "protocol": cipher_elem.get('sslversion', 'N/A'),
                "bits": cipher_elem.get('bits', 'N/A'),
                "strength": cipher_elem.get('strength', 'N/A'),
                "name": cipher_elem.get('cipher', 'N/A'), # 'cipher' attribute is the cipher name
                "id": cipher_elem.get('id', 'N/A') # Now explicitly extracting ID
            })

        # Certificate Details
        cert_elem = root.find('.//certificate')
        if cert_elem is not None:
            pk_elem = cert_elem.find('pk')
            scan_summary["certificate"] = {
                "common_name": cert_elem.findtext('subject', 'N/A'), # 'subject' for common name
                "issuer": cert_elem.findtext('issuer', 'N/A'),
                "serial": cert_elem.findtext('serial', 'N/A'), # This might be missing in short output
                "not_before": cert_elem.findtext('not-valid-before', 'N/A'),
                "not_after": cert_elem.findtext('not-valid-after', 'N/A'),
                "signature_algorithm": cert_elem.findtext('signature-algorithm', 'N/A'),
                "key_size": pk_elem.get('bits', 'N/A') if pk_elem is not None else 'N/A', # Key size from 'pk' tag
                "alt_names": [an.text for an in cert_elem.findall('altnames/altname')] if cert_elem.find('altnames') is not None else []
            }
        
        # Client CAs
        for ca_elem in root.findall('.//client-cas/ca'):
            scan_summary["client_cas"].append(ca_elem.get('name', 'N/A'))

        # Vulnerabilities (sslscan often lists these under notes or specific protocol/cipher flags)
        for heartbleed_elem in root.findall('.//heartbleed'):
            if heartbleed_elem.get('vulnerable') == '1':
                scan_summary["vulnerabilities"].append({
                    "type": "Heartbleed",
                    "name": f"Heartbleed ({heartbleed_elem.get('sslversion', 'N/A')})",
                    "description": "Vulnerable to Heartbleed"
                })
        
        # Add other vulnerabilities based on protocol/cipher notes
        for elem in root.iter():
            if elem.tag in ['protocol', 'cipher']:
                notes = elem.get('notes')
                if notes and ("vulnerable" in notes.lower() or "weak" in notes.lower()):
                    scan_summary["vulnerabilities"].append({
                        "type": elem.tag,
                        "name": elem.get('name') or elem.get('protocol') or elem.get('cipher') or elem.get('version'),
                        "description": notes
                    })
            # Check for specific vulnerability tags if sslscan provides them directly
            if elem.tag == 'vulnerability': # Hypothetical tag, check actual output
                 scan_summary["vulnerabilities"].append({
                    "type": elem.get('type', 'N/A'),
                    "name": elem.get('name', 'N/A'),
                    "description": elem.text or 'N/A'
                 })


        log(f"[+] SSLScan report '{os.path.basename(report_file)}' parsed successfully.")
        send_sse_event("ssl_report_parsed", scan_summary)
        return scan_summary

    except ET.ParseError as e:
        log(f"[!] Error parsing SSLScan XML report '{report_file}': {e}")
        return None
    except Exception as e:
        log(f"[!] Unexpected error parsing SSLScan report '{report_file}': {e}")
        return None

def clear_log_file():
    """Clears the content of the log output file."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log("[*] SSL log file cleared.")
    except Exception as e:
        log(f"[!] Error clearing SSL log file: {e}")

# Initialization check
if not elevate_if_needed():
    log("[!] Application might not function correctly due to insufficient Docker permissions.")

if __name__ == "__main__":
    log("Starting SSL Scanner demonstration...")
    clear_log_file() # Clear previous logs

    # Example: Scan Google's SSL configuration
    target = "hackthissite.org" # Specify host and port
    log(f"Attempting SSL Scan on: {target}")
    report_path = run_ssl_scan(target)
    
    if report_path:
        log(f"SSL Scan completed. Parsing report: {report_path}")
        summary = parse_ssl_report(report_path)
        if summary:
            print("\n--- SSL Scan Summary ---")
            print(f"Target: {summary.get('target')}")
            print(f"IP: {summary.get('ip')}")
            print(f"Port: {summary.get('port')}")
            print("\nProtocols:")
            for p in summary['protocols']:
                print(f"  - {p.get('name')} ({p.get('type')}, Enabled: {p.get('enabled')}) - {p.get('notes')}")
            print("\nCiphers:")
            for c in summary['ciphers']:
                print(f"  - {c.get('protocol')} {c.get('bits')} {c.get('strength')} {c.get('name')} (ID: {c.get('id')})")
            if summary['certificate']:
                print("\nCertificate:")
                for key, value in summary['certificate'].items():
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            if summary['client_cas']:
                print("\nClient CAs:")
                for ca in summary['client_cas']:
                    print(f"  - {ca}")
            if summary['vulnerabilities']:
                print("\nVulnerabilities:")
                for v in summary['vulnerabilities']:
                    print(f"  - {v['name']} ({v['type']}): {v['description']}")
        else:
            log("[!] Failed to parse SSL report.")
    else:
        log("[!] SSL Scan failed.")

    log("SSL Scanner demonstration finished.")

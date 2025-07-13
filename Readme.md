# NetShield Project Structure

This document provides a detailed overview of the NetShield project's directory structure and contents.

## Root Directory

- `app.py` - Main Flask application entry point
- `port_opener.py` - Utility for testing open ports (TCP/UDP)
- `project_structure.txt` - Project structure documentation
- `README.md` - Project overview and setup instructions
- `requirements.txt` - Python dependencies

## Services Directory (`/Services`)

Core scanning services and their implementations:

- `network_scanner.py` - Network scanning functionality (ports, OS detection, etc.)
- `ssl_scanner.py` - SSL/TLS scanning and analysis
- `zap_scanner.py` - Web application vulnerability scanning using OWASP ZAP
- `sql_map_scanner.py` - SQL injection scanning using SQLMap

### Services/Results Directory (`/Services/results`)

Stores scan results and reports:

- `network_scanner/` - Network scan results
- `ssl_scanner/` - SSL/TLS scan results
- `zap_scanner/` - Web application vulnerability scan results
- `sql_scanner/` - SQL injection scan results

## Routes Directory (`/routes`)

Flask blueprints for different application modules:

- `network_scanner_bp.py` - API endpoints for network scanning
- `ssl_scanner_bp.py` - API endpoints for SSL scanning
- `zap_scanner_bp.py` - API endpoints for ZAP scanning
- `chatbot_bp.py` - API endpoints for the chatbot assistant
- `__init__.py` - Package initialization

## Static Files (`/static`)

Frontend static files:

### CSS (`/static/css`)
- `style.css` - Main stylesheet

### JavaScript (`/static/js`)
- `chatbot.js` - Chatbot frontend logic
- `network_scanner.js` - Network scanner frontend logic
- `ssl_scanner.js` - SSL scanner frontend logic
- `zap_scanner.js` - ZAP scanner frontend logic
- `script.js` - Shared JavaScript utilities

## Templates (`/templates`)

HTML templates for the web interface:

- `home.html` - Main landing page
- `index.html` - Application entry point
- `network_scanner.html` - Network scanning interface
- `ssl_scanner.html` - SSL scanning interface
- `zap_scanner.html` - ZAP scanning interface
- `chatbot.html` - Chatbot interface

## Logs (`/logs`)

Application log files:

- `network_agent_log.txt` - Network scanner logs
- `ssl_agent_log.txt` - SSL scanner logs
- `zap_agent_log.txt` - ZAP scanner logs
- `sql_agent_log.txt` - SQL scanner logs
- `chatbot_logs.txt` - Chatbot interaction logs

## PDF Reports (`/pdfs`)

Generated PDF reports:

### Network Scanning Reports (`/pdfs/network_scanning`)
- `netshield_scan_aggressive.pdf` - Aggressive scan results
- `netshield_scan_fragmented.pdf` - Fragmented scan results
- `netshield_scan_os.pdf` - OS detection results
- `netshield_scan_tcp.pdf` - TCP scan results
- `netshield_scan_tcp_syn.pdf` - TCP SYN scan results

## Temp Directory (`/temp`)

Temporary files and development resources:

- `agent_linux.py` - Linux agent implementation
- `agent_windows.py` - Windows agent implementation
- `port_opener_linux.py` - Linux port testing utility
- `port_opener_windows.py` - Windows port testing utility
- `chatbot.js` - Development version of chatbot frontend
- `chatbot.html` - Development version of chatbot interface
- `scan_result.txt` - Temporary scan results
- `udp_result.txt` - UDP scan results
- `agent_log.txt` - Agent execution logs

### Templates (`/temp/templates`)
Temporary template files for development

## Uploads Directory (`/uploads`)

Directory for user-uploaded files during scans.

## Virtual Environment (`/venv`)

Python virtual environment (not included in version control).

## Python Cache (`/__pycache__`)

Python bytecode cache directories (automatically generated).

## Results Directory (`/results`)

Additional scan results and output files.

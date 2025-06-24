# NetShield - Network Port Scanner and Firewall Manager

NetShield is a powerful network security tool that combines port scanning and firewall management capabilities. It provides a user-friendly GUI to scan for open ports on local or remote systems and manage Windows Firewall rules to block or allow specific ports.

## Features

- **Port Scanning**:
  - TCP and UDP port scanning capabilities
  - Service and version detection
  - Process identification for open ports
  - Support for IP ranges and CIDR notation

- **Firewall Management**:
  - Create Windows Firewall rules to block/open ports
  - Whitelist specific ports to prevent blocking
  - Verify port status after applying rules

- **User Interface**:
  - Intuitive GUI built with Tkinter
  - Real-time logging
  - Visual indicators for scan progress
  - Port status display with service information

## Requirements

- Windows 10/11
- Python 3.7+
- Docker Desktop (for Nmap scanning)
- Administrator privileges (required for firewall operations)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/DivyViradiya07/NetShield.git
   cd NetShield
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Docker Desktop**:
   - Download and install Docker Desktop for Windows from [Docker's official website](https://www.docker.com/products/docker-desktop)
   - Ensure Docker is running before using NetShield

## Usage

1. **Run the application**:
   ```bash
   python agent.py
   ```
   Note: Run as Administrator for full functionality

2. **Using the GUI**:
   - **Detect IP**: Click to detect your local IP address
   - **Target**: Enter an IP address, range, or CIDR notation
   - **Scan**: Perform TCP or UDP scans
   - **Block Ports**: Block all detected open ports
   - **Whitelist**: Add ports to prevent them from being blocked

3. **Using port_opener.py (for testing)**:
   ```bash
   python port_opener.py
   ```
   This script opens multiple TCP and UDP ports for testing purposes.

## File Descriptions

- `agent.py`: Main application with GUI and core functionality
- `port_opener.py`: Utility to open test ports for demonstration
- `agent_log.txt`: Log file containing scan and operation history
- `scan_result.txt`: Results of the latest TCP scan
- `udp_result.txt`: Results of the latest UDP scan

## Security Notes

- Always run this tool with administrator privileges for full functionality
- Be cautious when blocking ports on production systems
- The tool creates Windows Firewall rules with the prefix "Block_NetShield_"
- Whitelist critical ports before performing bulk blocking operations

## Troubleshooting

- **Docker not found**: Ensure Docker Desktop is installed and running
- **Permission errors**: Run the application as Administrator
- **Scan failures**: Check if the target IP is reachable and not blocking ICMP/ping
- **Firewall rule issues**: Verify Windows Firewall service is running

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

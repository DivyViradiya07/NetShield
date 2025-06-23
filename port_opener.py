# open_ports_multi.py
import socket
import threading

TCP_PORTS = [9999, 8888, 7777, 6666, 5555, 4444, 3333, 2222, 1111, 8080]
UDP_PORTS = [53, 69, 161, 500, 514, 1111, 2222, 3333]  # Example UDP ports

def start_tcp_listener(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', port))
        s.listen()
        print(f"[+] TCP Listening on port {port}")
        s.accept()  # Keeps the port open
    except Exception as e:
        print(f"[!] Failed to open TCP port {port}: {e}")

def start_udp_listener(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', port))
        print(f"[+] UDP Listening on port {port}")
        while True:
            data, addr = s.recvfrom(1024)  # Wait for data to keep socket alive
    except Exception as e:
        print(f"[!] Failed to open UDP port {port}: {e}")

if __name__ == "__main__":
    # Start TCP listeners
    for port in TCP_PORTS:
        t = threading.Thread(target=start_tcp_listener, args=(port,), daemon=True)
        t.start()

    # Start UDP listeners
    for port in UDP_PORTS:
        t = threading.Thread(target=start_udp_listener, args=(port,), daemon=True)
        t.start()

    print("[*] All specified TCP and UDP ports are now open. Press Ctrl+C to stop.")
    try:
        while True:
            pass  # Keep main thread alive
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")

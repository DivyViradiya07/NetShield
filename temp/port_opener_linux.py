# open_ports_multi.py
import socket
import threading
import time

# Define the TCP ports to open
# These are example ports. Choose ports that are not commonly used by other services
# unless you specifically intend to simulate a service on a standard port.
TCP_PORTS = [9999, 8888, 7777, 6666, 5555, 4444, 3333, 2222, 1111, 8080]

# Define the UDP ports to open
# These are example ports. Choose ports that are not commonly used by other services.
UDP_PORTS = [53, 69, 161, 500, 514, 1111, 2222, 3333]

def start_tcp_listener(port):
    """
    Starts a TCP listener on the specified port.
    It binds to '0.0.0.0' to listen on all available network interfaces.
    The s.accept() call keeps the connection open, simulating a persistent service.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allows the socket to be reused immediately after it's closed,
        # preventing "Address already in use" errors.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(5) # Listen for up to 5 pending connections
        print(f"[+] TCP Listening on port {port}")
        conn, addr = s.accept() # This call blocks until a connection is made
        print(f"    [+] TCP connection established with {addr} on port {port}")
        # To keep the port "open" even after a connection, you might want to loop accept()
        # For this script, we just accept one connection to demonstrate it's open.
        # For a truly persistent server, you'd put the accept() and handling in a loop.
        conn.close() # Close the connection after accepting
        s.close() # Close the listening socket
    except Exception as e:
        print(f"[!] Failed to open TCP port {port}: {e}")

def start_udp_listener(port):
    """
    Starts a UDP listener on the specified port.
    It binds to '0.0.0.0' to listen on all available network interfaces.
    The loop with s.recvfrom(1024) keeps the socket alive and listens for incoming data.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allows the socket to be reused immediately after it's closed.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        print(f"[+] UDP Listening on port {port}")
        # This loop is crucial for UDP, as there are no "connections" to maintain.
        # It continuously waits for incoming data, keeping the port open.
        while True:
            data, addr = s.recvfrom(1024) # Buffer size is 1024 bytes
            print(f"    [+] UDP data received from {addr} on port {port}: {data.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"[!] Failed to open UDP port {port}: {e}")
    finally:
        s.close() # Ensure the socket is closed if the loop breaks

if __name__ == "__main__":
    # List to hold all thread objects
    threads = []

    # Start TCP listeners in separate threads
    for port in TCP_PORTS:
        t = threading.Thread(target=start_tcp_listener, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    # Start UDP listeners in separate threads
    for port in UDP_PORTS:
        t = threading.Thread(target=start_udp_listener, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    print("\n[*] All specified TCP and UDP ports are now attempting to open.")
    print("[*] Use 'netstat -tuln' or 'ss -tuln' in your Linux terminal to verify.")
    print("[*] Press Ctrl+C to stop the script.")

    try:
        # Keep the main thread alive. Daemon threads will automatically exit
        # when the main program exits.
        # A simple sleep loop is used here. For more robust applications,
        # you might use a signaling mechanism or join threads (though joining
        # daemon threads would defeat the purpose of them being daemon).
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    except Exception as e:
        print(f"[!] An error occurred in the main thread: {e}")

    print("[*] Port opener script terminated.")

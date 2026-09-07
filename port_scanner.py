import socket
import concurrent.futures

def scan_port(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET. socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex(target,port)
        if result == 0:
            try:
                #Banner grabbing 
                sock.sendall(b"Hello\r\n")
                banner = sock.recv(1024).decode.strip()
            except:
                banner = "No Banner"
            print(f"[+] port {port} Open - Banner: {banner}")
        sock.close()
    except Exception as e:
        print("Error on port {port} : {e}")

def scan_ports(target, ports, workers=100):
    print(f"Scanning {target}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers = workers) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    target_host = ""
    ports_to_scan = range(20, 1025)
    scan_ports(target_host, ports_to_scan)

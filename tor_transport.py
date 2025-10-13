
import socket
import socks

# Default Tor SOCKS5 proxy (local)
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def create_tor_socket(dest_host, dest_port, timeout=10):
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
    s.settimeout(timeout)
    s.connect((dest_host, dest_port))
    return s

def send_over_tor(host, port, data_bytes):
    try:
        s = create_tor_socket(host, port)
        s.sendall(data_bytes)
        response = s.recv(4096)
        s.close()
        return response
    except Exception as e:
        print("Tor send failed:", e)
        return None

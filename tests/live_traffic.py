"""Loopback traffic for the live `drift watch` check in CI: DNS lookups for an
allowed name and a tracker, and an HTTP request naming another host."""
import socket, struct, time, threading, http.server
def dns_query(name):
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(header + q, ("127.0.0.1", 53)); s.close()
time.sleep(3)
dns_query("allowed.example"); dns_query("tracker.example")
srv = http.server.HTTPServer(("127.0.0.1", 8080), http.server.SimpleHTTPRequestHandler)
threading.Thread(target=srv.handle_request, daemon=True).start()
c = socket.create_connection(("127.0.0.1", 8080)); c.sendall(b"GET / HTTP/1.1\r\nHost: telemetry.example\r\n\r\n"); c.recv(100); c.close()

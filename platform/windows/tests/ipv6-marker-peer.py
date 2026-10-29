"""Isolated IPv6 fixture: echo payloads and report protected-byte arrivals."""
import argparse
import socket
import socketserver
import threading

parser = argparse.ArgumentParser()
parser.add_argument("address")
parser.add_argument("port", type=int)
args = parser.parse_args()

class Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(90)
        try:
            while data := self.request.recv(1024):
                with self.server.counter_lock:
                    if data == b"?":
                        reply = str(self.server.protected_bytes).encode() + b"\n"
                    else:
                        self.server.protected_bytes += data.count(b"B")
                        reply = data
                self.request.sendall(reply)
        except (TimeoutError, ConnectionError):
            pass

with Server((args.address, args.port), Handler) as server:
    server.counter_lock = threading.Lock()
    server.protected_bytes = 0
    server.serve_forever()

"""Independent UDP delivery counter; TCP queries do not share the tested bind."""
import json
import selectors
import socket
import sys


def main():
    address, port = sys.argv[1], int(sys.argv[2])
    counts = {"A": 0, "B": 0, "R": 0}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as control, \
            selectors.DefaultSelector() as events:
        udp.bind((address, port))
        control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control.bind((address, port))
        control.listen(4)
        events.register(udp, selectors.EVENT_READ)
        events.register(control, selectors.EVENT_READ)
        print("READY", flush=True)
        while True:
            for key, _ in events.select():
                if key.fileobj is udp:
                    payload, _ = udp.recvfrom(4096)
                    marker = payload.decode("ascii", errors="replace")
                    if marker in counts:
                        counts[marker] += 1
                    continue
                client, _ = control.accept()
                with client:
                    client.settimeout(2)
                    client.sendall((json.dumps(counts) + "\n").encode("ascii"))


if __name__ == "__main__":
    main()

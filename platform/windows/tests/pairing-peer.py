"""Loopback-only TLS-PSK protocol fixture; never creates adapters or routes.

Requires Python 3.13+. Forward its port over SSH for Windows VM testing.
All credentials here are public test values, not usable with a real Saslik.
"""

import base64
import json
import socket
import ssl
import time


def main():
    key = b"p" * 32
    encoded = base64.urlsafe_b64encode(key).decode().rstrip("=")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_psk_server_callback(
        lambda identity: key if identity in {"fixture-invitation", "fixture-client"} else b""
    )
    active = None
    generation = 0
    actions = []
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 18767))
        listener.listen(1)
        listener.settimeout(5)
        print("Fixture ready on loopback:18767", flush=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            with raw:
                raw.settimeout(5)
                try:
                    with context.wrap_socket(raw, server_side=True) as connection:
                        request = b""
                        while not request.endswith(b"\n") and len(request) <= 8192:
                            chunk = connection.recv(4096)
                            if not chunk:
                                raise ValueError("Truncated request")
                            request += chunk
                        if len(request) > 8192:
                            raise ValueError("Oversized request")
                        message = json.loads(request)
                        action = message["action"]
                        actions.append(action)
                        response = {"ok": True}
                        if action == "enroll":
                            response = {"identity": "fixture-client", "psk": encoded}
                        elif action == "tunnel-open":
                            if active is None:
                                generation += 1
                                active = f"{generation:064x}"
                            response = endpoint(active)
                        elif action == "tunnel-heartbeat":
                            response = endpoint(active) if message.get("context") == active else {"error": "stale"}
                        elif action == "tunnel-close":
                            active = None
                        elif action not in {"commit", "status"}:
                            response = {"error": "unsupported"}
                        connection.sendall(json.dumps(response).encode() + b"\n")
                except (ssl.SSLError, ValueError, OSError):
                    # A deliberately invalid PSK must not terminate the listener.
                    continue
            if actions.count("tunnel-close") == 2:
                expected = ["enroll", "commit", "tunnel-open", "tunnel-heartbeat",
                            "tunnel-open", "tunnel-close", "tunnel-open",
                            "tunnel-heartbeat", "tunnel-close"]
                if actions != expected:
                    raise RuntimeError(f"Unexpected control sequence: {actions}")
                print("PASS: enrollment, lease reuse, renewal, close and stale rejection", flush=True)
                return
    raise RuntimeError("Control fixture timed out")


def endpoint(context):
    return {"ok": True, "lease_seconds": 60, "tunnel": {
        "version": 1, "transport": "tuntom", "id": 242, "port": 40242,
        "context": context, "client_interface": "skt242c", "server_interface": "skt242s",
        "server_address": "10.250.242.1/30", "client_address": "10.250.242.2/30",
    }}


if __name__ == "__main__":
    main()

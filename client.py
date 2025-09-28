"""
What this script does:
1) Builds a client side SSLContext.
2) Supports three modes:
   - insecure: no certificate validation  this is used to demonstrating MITM success.
   - validate: standard PKI validation using CA + hostname.
   - pin: PKI validation + certificate pinning using SHA-256 of the server cert.
3) Connects to the server, sends message, and prints the echoed response.

Example for validating against a legit server:
python3 client.py --mode validate --host 10.0.0.2 --server-name chat.local \
  --cafile server.crt --port 5443

Example for pinning against a legit server:
python3 client.py --mode pin --host 10.0.0.2 --server-name chat.local \
  --cafile server.crt --pin 0CC3...A253 --port 5443

Example when being insecure to an attacker:
python3 client.py --mode insecure --host 10.0.0.3 --server-name chat.local --port 5443
"""

import socket, ssl, sys, argparse, hashlib

# Prefer TLS 1.3 as the minimum version
def get_tls_version_min():
    try:
        from ssl import TLSVersion
        return TLSVersion.TLSv1_3
    except Exception:
        return None

# Hex-encoded SHA-256 of the cert
def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest().upper()

# Build SSL context, apply mode, connect and echo
def connect_and_chat(host, port, mode, server_name, cafile=None, pin=None):
    ctx = ssl.create_default_context()
    vmin = get_tls_version_min()
    if vmin is not None:
        try:
            ctx.minimum_version = vmin
        except Exception:
            pass

    # Mode switches, insecure disables validation and validate/pin enable it
    if mode == "insecure":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        if cafile:
            ctx.load_verify_locations(cafile=cafile)

    # TCP connect, wrap with TLS, the optional pin check, interactive echo loop
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name) as s:
            if mode == "pin":
                der = s.getpeercert(binary_form=True)
                got = sha256_hex(der)
                if pin is None:
                    raise ssl.SSLError("Pinning selected but --pin not provided")
                if got != pin.upper():
                    raise ssl.SSLError(f"Pinning failed. Expected {pin.upper()}, got {got}")
                print(f"[PIN OK] {server_name} fingerprint matched {got}")
            print(f"Connected ({mode}). Type messages, Ctrl+C to quit.")
            for line in sys.stdin:
                s.sendall(line.encode())
                resp = s.recv(4096)
                if not resp:
                    print("Connection closed by server.")
                    break
                print("Echo:", resp.decode(errors="ignore").rstrip())

# Parse args and run
def main():
    ap = argparse.ArgumentParser(description="TLS Chat Client")
    ap.add_argument("--mode", choices=["insecure", "validate", "pin"], required=True)
    ap.add_argument("--host", default="chat.local")
    ap.add_argument("--port", type=int, default=5443)
    ap.add_argument("--server-name", default="chat.local")
    ap.add_argument("--cafile", default=None)
    ap.add_argument("--pin")
    args = ap.parse_args()

    try:
        connect_and_chat(args.host, args.port, args.mode, args.server_name, args.cafile, args.pin)
    except KeyboardInterrupt:
        print("\n[INFO] Bye.")
    except ssl.SSLError as e:
        print(f"[SSL ERROR] {e}")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()

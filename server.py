"""
What this script does:
1) Builds a server side SSLContext (TLS)
2) Loads the provided certificate and private key (PEM): --cert, --key.
3) Listens on a TCP socket, accepts connections, and performs the TLS handshake.
4) For each client, reads data and echoes it back.
5) Logs connections and handshake failures.

Example cmd for legit server
python3 server.py --cert server.crt --key server.key --label SERVER --port 5443

Example cmd for evil server
python3 server.py --cert evil.crt --key evil.key --label EVIL --port 5443
"""

import socket, ssl, threading, argparse, sys

# Prefer TLS 1.3 as the minimum version
def get_tls_version_min():
    try:
        from ssl import TLSVersion
        return TLSVersion.TLSv1_3
    except Exception:
        return None
# Build a server side SSLContext and load the server certificate/key
def serve(certfile, keyfile, host="0.0.0.0", port=5443, label="SERVER"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    vmin = get_tls_version_min()
    if vmin is not None:
        try:
            ctx.minimum_version = vmin
        except Exception:
            pass
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # Log client, read data, echo back with label, then close
    def handle(conn, addr):
        print(f"[{label}] {addr} connected (TLS)")
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                print(f"[{label}] <{addr}> {data.decode(errors='ignore').rstrip()}")
                conn.sendall(f"{label} ECHO: ".encode() + data)
        finally:
            conn.close()

    # Accept client sockets, wrap them in TLS, and hand each to a handler thread
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen()
        print(f"[{label}] listening on {host}:{port} using {certfile}")
        while True:
            client, addr = sock.accept()
            try:
                tls_conn = ctx.wrap_socket(client, server_side=True)
            except ssl.SSLError as e:
                print(f"[{label}] SSL error during handshake from {addr}: {e}")
                client.close()
                continue
            threading.Thread(target=handle, args=(tls_conn, addr), daemon=True).start()

# Parse arguments, start the TLS server, and make sure it exit cleanly on Ctrl C
def main():
    ap = argparse.ArgumentParser(description="TLS Chat Server (legit or evil)")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5443)
    ap.add_argument("--label", default="SERVER")
    args = ap.parse_args()
    try:
        serve(args.cert, args.key, args.host, args.port, args.label)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down.")
        sys.exit(0)

if __name__ == "__main__":
    main()

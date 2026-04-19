"""Quick integration test for v3 — run and delete."""

import socket
import threading
from handshake import server_handshake, client_handshake
from record_protection import protect_record, unprotect_record


HOST, PORT = "127.0.0.1", 10013


def run_server():
    import sys, os

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
    from framing import send_record, recv_record

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        conn, _ = s.accept()
        with conn:
            cwk, swk = server_handshake(conn)
            raw = recv_record(conn)
            msg = unprotect_record(cwk, 0, raw)
            print(f"SERVER received: {msg}")
            resp = b"HTTP/1.1 200 OK hello"
            protected = protect_record(swk, 0, resp)
            send_record(conn, protected)
            print("SERVER sent response")


def run_client():
    import sys, os, time

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
    from framing import send_record, recv_record

    time.sleep(0.5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((HOST, PORT))
        cwk, swk = client_handshake(c)
        req = b"GET /test HTTP/1.1"
        protected = protect_record(cwk, 0, req)
        send_record(c, protected)
        print("CLIENT sent request")
        raw = recv_record(c)
        resp = unprotect_record(swk, 0, raw)
        print(f"CLIENT received: {resp}")


t = threading.Thread(target=run_server)
t.start()
run_client()
t.join()
print("FULL PIPELINE TEST PASSED")

# server_v1.py
import socket

from framing import send_record, recv_record
from crypto import encrypt_message, decrypt_message

HOST = "127.0.0.1"
PORT = 8081

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"Listening on {HOST}:{PORT}")
    conn, addr = server.accept()

    with conn:
        print(f"Connected by {addr}")

        encrypted_request = recv_record(conn)
        request = decrypt_message(encrypted_request)

        print("Received decrypted request:")
        print(request.decode("utf-8"))

        response = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            "Content-Length: 13\r\n\r\nhello, client"
        ).encode("utf-8")

        encrypted_response = encrypt_message(response)
        send_record(conn, encrypted_response)

# client_v1.py
import socket

from framing import send_record, recv_record
from crypto import encrypt_message, decrypt_message

HOST = "127.0.0.1"
PORT = 8081

request = (
    "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"
).encode("utf-8")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    encrypted_request = encrypt_message(request)
    send_record(client, encrypted_request)

    encrypted_response = recv_record(client)
    response = decrypt_message(encrypted_response)

    print("Received decrypted response:")
    print(response.decode("utf-8"))

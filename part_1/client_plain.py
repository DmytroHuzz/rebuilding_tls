# client_plain.py
import socket

HOST = "127.0.0.1"
PORT = 8081

request = "GET /transfer?to=bob&amount=100 HTTP/1.1\r\nHost: localhost\r\n\r\n"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    client.sendall(request.encode("utf-8"))

    response = client.recv(4096)
    print("Received response:")
    print(response.decode("utf-8"))

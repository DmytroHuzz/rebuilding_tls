# server_plain.py
import socket

HOST = "127.0.0.1"
PORT = 8081

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"Listening on {HOST}:{PORT}")
    conn, addr = server.accept()

    with conn:
        print(f"Connected by {addr}")

        data = conn.recv(4096)
        request = data.decode("utf-8")
        print("Received request:")
        print(request)

        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "hello, client"
        )
        conn.sendall(response.encode("utf-8"))

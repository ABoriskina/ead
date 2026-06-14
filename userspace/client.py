import socket
import time

HOST = "127.0.0.1"
PORT = 5000

while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((HOST, PORT))
            client.sendall(b"hello")

            print("Sent hello")

    except ConnectionRefusedError:
        print("Server is not available")

    time.sleep(3)

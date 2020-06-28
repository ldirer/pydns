

import socket
import threading


# Message has 5 parts:
# 1. Header
# 2. Question
# 3. Answer
# 4. Authority
# 5. Additional
from message import parse_message


def handle_message(s: socket.socket, data, emitter):
    print(f"emitter: {emitter}")
    print(f"received data: {data}")
    # print(f"decoded {data.decode('utf-8')}")
    m = parse_message(data)
    print(f"Parsed message: {m}")
    s.sendto(data, emitter)


def main():
    host, port = '127.0.0.1', 9000
    # SOCK_DGRAM for a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))

    # server_socket.listen()
    print(f"listening on {host}:{port}")
    while True:
        # client_socket, client_addr = server_socket.accept()
        data, client_addr = server_socket.recvfrom(4096)
        # start any number of threads. Yolo.
        threading.Thread(target=handle_message, args=(server_socket, data, client_addr)).start()


if __name__ == '__main__':
    main()

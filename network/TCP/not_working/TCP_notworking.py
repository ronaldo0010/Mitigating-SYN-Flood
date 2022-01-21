import socket
import os


SEPARATOR = "\t"
BUFFER_SIZE = 65535
HOST = "localhost"
PORT = 5000


def main():
    sock = init_server(host=HOST, port=PORT)

    sock.close()




def init_server(host="localhost", port=5000):
        sock = socket.socket()
        sock.connect((HOST, PORT))
        return sock




if __name__ == "__main__":
    main('hello.txt')
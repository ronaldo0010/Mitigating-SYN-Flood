import socket

def startReciever():
    SERVER_HOST = "localhost"
    SERVER_PORT = 5000

    sock = socket.socket()
    sock.bind((SERVER_HOST, SERVER_PORT))

    sock.listen(1)

    client_socket, address = sock.accept()


    client_socket.close()
    sock.close()

if __name__ == "__main__":
    startReciever()
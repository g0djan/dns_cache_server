from socket import socket

BUFFER_SIZE = 1024


class Request:
    def __init__(self, socket_: socket, address: tuple):
        self.socket = socket_
        self.address = address
        self.msg = self._read()

    def _read(self):
        while True:
            data = self.socket.recv(BUFFER_SIZE)
            return DNSFrame(data)

    def reply(self, msg):

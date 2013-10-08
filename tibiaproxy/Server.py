import socket


class Server:

    def __init__(self, destination_host, destination_port,
                 listen_host, listen_port):
        self.destination_host = destination_host
        self.destination_port = int(destination_port)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.listen_host, self.listen_port))

    def run(self):
        print(("Listening on address %s:%s, connections will be forwarded " +
               "to %s:%s") % (self.listen_host, self.listen_port,
                              self.destination_host, self.destination_port))

        self.s.listen(1)
        conn, addr = self.s.accept()
        print("Received a connection from %s:%s" % addr)

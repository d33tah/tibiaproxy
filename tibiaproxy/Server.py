class Server:

    def __init__(self, destination_host, destination_port,
                 listen_host, listen_port):
        self.destination_host = destination_host
        self.destination_port = int(destination_port)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)

    def run(self):
        print(("Listening on address %s:%s, connections will be forwarded " +
               "to %s:%s") % (self.destination_host, self.destination_port,
                              self.listen_host, self.listen_port))

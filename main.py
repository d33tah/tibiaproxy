#!/usr/bin/python

import config
from tibiaproxy.Server import Server

if __name__ == '__main__':
    s = Server(config.destination_host, config.destination_port,
               config.listen_host, config.listen_port)
    s.run()

# The server address and port number the proxy has to connect to.
destination_host = '127.0.0.1'
destination_port = '7172'

# The server address and port number the proxy will listen on.
listen_host = '127.0.0.1'
listen_port = '7171'

# The server address and port number that will be sent to the client.
# Change it only if you're behind a NAT. Defaults to the listen address.
announce_host = listen_host
announce_port = listen_port

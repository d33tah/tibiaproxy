real_tibia = False

# The login server address and port number the proxy has to connect to.
destination_login_host = '127.0.0.1'
destination_login_port = '7172'

# The game server address and port number the proxy has to connect to.
destination_game_host = '127.0.0.1'
destination_game_port = '7173'

# The server address and port number the
# login part of the proxy will listen on.
listen_login_host = '127.0.0.1'
listen_login_port = '7171'

# The server address and port number the game server part of the proxy
# will listen on. Defaults to the host being the same as for the login part
# and port equal to login port minus one.
listen_game_host = listen_login_host
listen_game_port = int(listen_login_port) - 1

# The server address and port number that will be sent to the client.
# Change it only if you're behind a NAT. Defaults to the listen address.
announce_host = listen_login_host
announce_port = listen_game_port

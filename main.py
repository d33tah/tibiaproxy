#!/usr/bin/python

"""
This file is part of tibiaproxy.

tibiaproxy is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Joggertester is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
"""

import config
from tibiaproxy.Server import Server

if __name__ == '__main__':
    s = Server(destination_login_host=config.destination_login_host,
               destination_login_port=config.destination_login_port,
               listen_login_host=config.listen_login_host,
               listen_login_port=config.listen_login_port,
               listen_game_host=config.listen_game_host,
               listen_game_port=config.listen_game_port,
               announce_host=config.announce_host,
               announce_port=config.announce_port,
               real_tibia=config.real_tibia,
               debug=config.debug)
    s.run()

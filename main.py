#!/usr/bin/python

"""tibiaproxy's entry point."""

#This file is part of tibiaproxy.
#
#Tibiaproxy is free software; you can redistribute it and/or modify
#It under the terms of the GNU General Public License as published by
#The Free Software Foundation; either version 2 of the License, or
#(at your option) any later version.
#
#Joggertester is distributed in the hope that it will be useful,
#But WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#Along with Foobar; if not, write to the Free Software
#Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import sys
import config
import importlib
import os

from tibiaproxy.Server import Server
from tibiaproxy.util import log


def main():
    """tibiaproxy's entry point."""
    plugins = []
    for filename in os.listdir('plugins'):
        if filename == "__init__.py" or filename[-3:] != ".py":
            continue
        plugin_name = filename[:-3]
        plugins += [importlib.import_module('plugins.' + plugin_name)]
        log("Loaded plugin %s." % plugin_name)

    server = Server(destination_login_host=config.destination_login_host,
                    destination_login_port=config.destination_login_port,
                    listen_login_host=config.listen_login_host,
                    listen_login_port=config.listen_login_port,
                    listen_game_host=config.listen_game_host,
                    listen_game_port=config.listen_game_port,
                    announce_host=config.announce_host,
                    announce_port=config.announce_port,
                    real_tibia=config.real_tibia,
                    debug=config.debug,
                    plugins=plugins)
    server.run()


def run_pdb_hook(*args, **kwargs):
    """Debug mode exception handler. Drops into a debugger shell"""

    import traceback

    # load ipdb if possible, otherwise fall back to pdb
    try:
        import ipdb as pdb
    except ImportError:
        import pdb

    # if it's a KeyboardInterrupt, ignore it and just tell it and quit.
    if isinstance(args[1], KeyboardInterrupt):
        sys.exit("Caught a KeyboardInterrupt, quitting.")

    traceback.print_exception(*args, **kwargs)
    pdb.pm()

if __name__ == '__main__':
    if config.debug:
        sys.excepthook = run_pdb_hook
    main()

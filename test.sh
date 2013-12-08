#!/bin/bash

# test.sh
#
# Sends a login and game handshake to the proxy, with account, password set to
# 1 and character name set to 11. Disconnects after five seconds.
#
# Usage:
#
# ./test.sh

ncat -4 localhost 7171 < test/login.bin
(cat test/game.bin; sleep 5) | ncat -4 localhost 7170

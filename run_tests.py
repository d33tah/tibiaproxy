#!/usr/bin/python

import main
import socket
import threading
import time

l_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
l_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l_s.bind(("127.0.0.1", 7172))

g_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
g_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
g_s.bind(("127.0.0.1", 7169))

def reply_with_charlist(l_s):
    l_s.listen(1)
    s, _ = l_s.accept()
    s.send(open("test/login-response.bin", "rb").read())
    s.close()

def reply_with_game(g_s):
    g_s.listen(1)
    s, _ = g_s.accept()
    s.send(open("test/game-response.bin", "rb").read())
    s.close()

def request_charlist():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 7171))
    s.send(open("test/login.bin", "rb").read())
    s.close()

def request_game():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 7170))

    size = s.recv(1)
    assert(s.recv(1) == b'\x00')
    s.recv(ord(size))

    s.send(open("test/game.bin", "rb").read())
    time.sleep(0.2)
    s.close()

threading.Thread(target=reply_with_charlist, args=(l_s,)).start()
threading.Thread(target=reply_with_game, args=(g_s,)).start()
threading.Timer(0.1, request_charlist).start()
threading.Timer(0.2, request_game).start()

main.tibiaproxy_main({
    'announce_host': '127.0.0.1',
    'announce_port': 7170,
    'debug': True,
    'destination_login_host': '127.0.0.1',
    'destination_login_port': '7172',
    'listen_game_host': '127.0.0.1',
    'listen_game_port': 7170,
    'listen_login_host': '127.0.0.1',
    'listen_login_port': '7171',
    'real_tibia': False
})

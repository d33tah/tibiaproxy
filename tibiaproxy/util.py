import sys


def log(_str):
    sys.stderr.write(_str + "\n")
    sys.stderr.flush()

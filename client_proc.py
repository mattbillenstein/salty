#!/usr/bin/env python3

import gevent.monkey
gevent.monkey.patch_all()

from server import ClientProc

import socket
import sys
import time

sock, server_q, keyroot, fileroot = sys.argv[1:]
sock = socket.fromfd(int(sock), socket.AF_INET, socket.SOCK_STREAM)
server_q = socket.fromfd(int(server_q), socket.AF_INET, socket.SOCK_STREAM)

ClientProc(sock, server_q, keyroot, fileroot).serve_forever()

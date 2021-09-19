#!/usr/bin/env python3

import gevent.monkey
gevent.monkey.patch_all()

import json
import os
import os.path
import socket
import ssl
import struct
import sys
import time
import uuid
from queue import Queue
from pprint import pprint

import gevent
import gevent.server
import msgpack
from gevent.event import AsyncResult


class Reactor(object):

    def send_msg(self, sock, msg):
        data = msgpack.packb(msg)
        data = struct.pack('!I', len(data)) + data
        if isinstance(sock, Queue):
            sock.put(data)
            return len(data)
        return sock.send(data)

    def recv_msg(self, sock):
        data = sock.read(4)
        if not data:
            return None
        size = struct.unpack('!I', data)[0]
        msg = msgpack.unpackb(sock.read(size))
        return msg

    def _writer(self, sock, q):
        while 1:
            msg = q.get()
            sock.send(msg)

    def handle(self, sock, addr):
        print(f'Connection established {addr[0]}:{addr[1]}')
        client_id = None
        q = Queue()
        g = gevent.spawn(self._writer, sock, q)
        try:
            while 1:
                try:
                    msg = self.recv_msg(sock)
                    if not msg:
                        print(f'Connection disconnected {addr[0]}:{addr[1]}')
                        break
                    if msg['type'] == 'identify':
                        client_id = msg['id']
                        self.clients[client_id] = q
                    else:
                        self.handle_msg(msg, q)
                except ConnectionResetError:
                    print(f'Connection lost {addr[0]}:{addr[1]}')
                    break
        finally:
            if client_id:
                self.clients.pop(client_id)
            g.kill()

class SaltyServer(gevent.server.StreamServer, Reactor):
    def __init__(self, *args, **kwargs):
        self.id = 'server'
        self.clients = {}
        super().__init__(*args, **kwargs)

    def handle_msg(self, msg, q):
        if msg['type'] == 'ping':
            self.send_msg(q, {'type': 'pong'})
        elif msg['type'] == 'get_file':
            path = os.path.join('files', msg['path'])
            with open(path, 'rb') as f:
                data = f.read()
            msg['type'] = 'send_file'
            msg['data'] = data
            self.send_msg(q, msg)
        else:
            print(f'Unhandled message: {msg}')

class SaltyClient(Reactor):
    def __init__(self, addr, id, keyfile, certfile):
        self.id = id
        self.addr = addr
        self.keyfile = keyfile
        self.certfile = certfile
        self.futures = {}

    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock = ssl.wrap_socket(
            sock,
            keyfile=self.keyfile,
            certfile=self.certfile,
        )
        sock.connect(self.addr)
        return sock

    def handle_msg(self, msg, q):
        if msg['type'] == 'pong':
            pass
        elif msg['type'] == 'send_file':
            ar = self.futures.pop(msg['future_id'], None)
            if ar:
                ar.set(msg)
        else:
            print(f'Unhandled message: {msg}')

    def get_file(self, sock, path):
        id = str(uuid.uuid4())
        self.futures[id] = ar = AsyncResult()
        self.send_msg(sock, {'type': 'get_file', 'path': path, 'future_id': id})
        return ar.get()

    def serve_forever(self):
        while 1:
            sock = self._connect()
            g = gevent.spawn(self.handle, sock, self.addr)

            self.send_msg(sock, {'type': 'identify', 'id': self.id})
            while 1:
                self.send_msg(sock, {'type': 'ping'})
                time.sleep(5)

            g.join()

    def run(self, msg):
        sock = self._connect()
        self.send_msg(sock, msg)
        return self.recv_msg(sock)

def main(mode, hostport, *args):
    hostport = hostport.split(':')
    hostport = (hostport[0], int(hostport[1]))
    if mode == 'server':
        SaltyServer(hostport, keyfile='key.pem', certfile='cert.pem').serve_forever()
    elif mode == 'client':
        id = args[0]
        SaltyClient(hostport, id, keyfile='key.pem', certfile='cert.pem').serve_forever()
    elif mode == 'cli':
        msg = json.loads(args[0])
        result = SaltyClient(hostport, None, keyfile='key.pem', certfile='cert.pem').run(msg)
        pprint(result, indent=4)
    return 0

if __name__ == '__main__':
    main(*sys.argv[1:])

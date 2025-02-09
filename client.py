import os
import os.path
import socket
import ssl
import time
import traceback
from queue import Queue

from lib import operators
from lib.compat import get_facts
from lib.net import Reactor
from lib.util import elapsed, log, log_error, spawn_thread

class SaltyClient(Reactor):
    def __init__(self, addr, keyroot=os.getcwd(), id=None, path=''):
        self.addr = addr
        self.id = id
        self.keyroot = keyroot
        self.path = path
        self.futures = {}
        self._last_pong = time.time()

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = self.wrap_socket(sock)
        sock.connect(self.addr)
        return sock

    def handle_pong(self, msg, q):
        self._last_pong = time.time()

    def handle_run(self, msg, q):
        start = time.time()

        def get_file(path, **opts):
            msg = self.get_file(q, path, **opts)
            assert not msg.get('error'), msg['error']
            return msg

        def syncdir_get_file(path):
            msg = self.syncdir_get_file(q, path)
            assert not msg.get('error'), msg['error']
            return msg

        def syncdir_scandir(path):
            msg = self.syncdir_scandir(q, path)
            assert not msg.get('error'), msg['error']
            return msg['data']

        def server_shell(cmds, **kwds):
            msg = self.server_shell(q, cmds, **kwds)
            assert not msg.get('error'), msg['error']
            return msg['data']

        content = msg.pop('content')
        results, output = operators.run(
            content,
            msg['context'],
            start,
            self.path,
            get_file,
            syncdir_get_file,
            syncdir_scandir,
            server_shell,
        )

        msg['type'] = 'future'
        msg['result'] = {'results': results, 'output': '\n'.join(output), 'elapsed': elapsed(start)}
        self.send_msg(q, msg)

        rc = sum(_['rc'] for _ in results)
        log(f'Run {msg["context"]["id"]} {msg["context"]["role"]} {rc} {msg["result"]["elapsed"]:.6f}')

    def get_file(self, sock, path, **opts):
        msg = {'type': 'get_file', 'path': path}
        msg.update(opts)
        return self.do_rpc(sock, msg)

    def syncdir_get_file(self, sock, path):
        msg = {'type': 'syncdir_get_file', 'path': path}
        return self.do_rpc(sock, msg)

    def syncdir_scandir(self, sock, path):
        msg = {'type': 'syncdir_scandir', 'path': path}
        return self.do_rpc(sock, msg)

    def server_shell(self, sock, cmds, **kwds):
        msg = {'type': 'server_shell', 'cmds': cmds, 'kwds': kwds}
        return self.do_rpc(sock, msg)

    def handle(self, sock, addr):
        log(f'Connection established {addr[0]}:{addr[1]}')
        client_id = None
        q = Queue()
        g = spawn_thread(self._writer, (sock, q))
        p = spawn_thread(self._pinger, (q,))
        self.send_msg(q, {'type': 'identify', 'id': self.id, 'facts': get_facts()})

        try:
            while 1:
                try:
                    # if writer dead, break and eventually close the socket...
                    if not g.is_alive() or not p.is_alive():
                        break

                    msg = self.recv_msg(sock)
                    if msg is None:
                        log(f'Lost connection {addr[0]}:{addr[1]}')
                        break
                    self.handle_msg(msg, q)
                except OSError:
                    log(f'Connection lost {addr[0]}:{addr[1]}')
                    break
        finally:
            sock.close()

    def serve_forever(self):
        while 1:
            sock = None
            try:
                sock = self.connect()
                self.handle(sock, self.addr)
            except KeyboardInterrupt:
                break
            except Exception:
                tb = traceback.format_exc().strip()
                log_error('Exception in client serve:\n', tb)
                time.sleep(3)
            finally:
                if sock:
                    sock.close()

    def run(self, msg):
        sock = self.connect()
        self.send_msg(sock, msg)

        start = time.time()
        while 1:
            try:
                msg = self.recv_msg(sock) #, timeout=5)
                if msg['type'] != 'pong':
                    return msg
                log(f'Working {int(time.time()-start):} seconds ...', end='\r')
            except Exception as e:
                self.send_msg(sock, {'type': 'ping'})

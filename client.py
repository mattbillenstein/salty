import os
import os.path
import socket
import ssl
import time
import traceback
from queue import Queue

from lib import operators
from lib.compat import get_facts
from lib.net import Reactor, Socket, wrap_socket
from lib.util import elapsed, log, log_error, spawn_thread

PING_INTERVAL = 10.0
FACTS_INTERVAL = 60.0

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
        sock = wrap_socket(sock, self.keyroot)
        sock.connect(self.addr)
        return Socket(sock)

    def handle_run(self, msg, sock):
        start = time.time()

        def get_file(path, **opts):
            msg = self.get_file(sock, path, **opts)
            assert not msg.get('error'), msg['error']
            return msg

        def syncdir_get_file(path):
            msg = self.syncdir_get_file(sock, path)
            assert not msg.get('error'), msg['error']
            return msg

        def syncdir_scandir(path):
            msg = self.syncdir_scandir(sock, path)
            assert not msg.get('error'), msg['error']
            return msg['data']

        def server_shell(cmds, **kwds):
            msg = self.server_shell(sock, cmds, **kwds)
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
        sock.send_msg(msg)

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

    def handle_pong(self, msg, sock):
        self._last_pong = time.time()

    def _pinger(self, sock):
        time.sleep(PING_INTERVAL)
        last_facts = time.time()
        while 1:
            now = time.time()
            msg = {'type': 'ping'}
            if now - last_facts > FACTS_INTERVAL:
                # re-send facts every ~1m
                msg['id'] = self.id
                msg['facts'] = get_facts()
                last_facts = now
            sock.send_msg(msg)
            time.sleep(PING_INTERVAL)

            # if no pong back, break
            if (self._last_pong - now) > (PING_INTERVAL * 1.5):
                log_error('MISSING PONG', self._last_pong - now)
                break

    def handle(self, sock, addr):
        log(f'Connection established {addr[0]}:{addr[1]}')
        try:
            sock.send_msg({'type': 'identify', 'id': self.id, 'facts': get_facts()})
            p = spawn_thread(self._pinger, (sock,))
            while 1:
                try:
                    if not sock.is_alive():
                        log(f'Socket dead? {addr[0]}:{addr[1]}')
                        break
                    if not p.is_alive():
                        log(f'Pinger dead? {addr[0]}:{addr[1]}')
                        break

                    msg = sock.recv_msg()
                    if msg is None:
                        log(f'Connection dead {addr[0]}:{addr[1]}')
                        break
                    self.handle_msg(msg, sock)
                except OSError as e:
                    log(f'Connection lost {addr[0]}:{addr[1]} {e}')
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
        sock.send_msg(msg)

        start = time.time()
        running = True
        def logit():
            while running:
                time.sleep(5)
                log(f'Working {int(time.time()-start):} seconds ...', end='\r')
        t = spawn_thread(logit)

        while 1:
            msg = sock.recv_msg()
            if msg['type'] != 'pong':
                running = False
                break

        return msg

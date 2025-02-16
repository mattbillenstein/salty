import os
import os.path
import socket
import ssl
import time
import traceback
from queue import Queue

import gevent

from lib import operators
from lib.net import MsgMixin, ConnectionTimeout
from lib.util import elapsed, get_facts, log, log_error

PING_INTERVAL = 10.0
FACTS_INTERVAL = 60.0

class SaltyClient(MsgMixin):
    def __init__(self, addr, keyroot=os.getcwd(), id=None, path=''):
        self.addr = addr
        self.id = id
        self.keyroot = keyroot
        self.path = path
        self._last_pong = time.time()
        self.futures = {}

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.load_cert_chain(
            certfile=os.path.join(self.keyroot, 'cert.pem'),
            keyfile=os.path.join(self.keyroot, 'key.pem'),
        )
        ctx.load_verify_locations(os.path.join(self.keyroot, 'cert.pem'))
        sock = ctx.wrap_socket(sock)
        sock.connect(self.addr)
        return sock

    def handle_pong(self, msg, q):
        self._last_pong = time.time()

    def handle_run(self, msg, q):
        # Run a role on this client and report back results of each command
        start = time.time()

        # these closures mainly capture the Queue that we write the rpcs to
        # during the run for these functions which get injected into the global
        # namespace for the role python file being exec'd
        def get_file(path, **opts):
            msg = self.get_file(q, path, **opts)
            assert not msg.get('error'), msg['error']
            return msg

        def syncdir_get_file(path):
            msg = self.syncdir_get_file(q, path)
            assert not msg.get('error'), msg['error']
            return msg

        def syncdir_scandir(path, exclude=None):
            msg = self.syncdir_scandir(q, path, exclude=exclude)
            assert not msg.get('error'), msg['error']
            return msg['data']

        def server_shell(cmds, **kwds):
            msg = self.server_shell(q, cmds, **kwds)
            assert not msg.get('error'), msg['error']
            return msg['data']

        content = msg.pop('content')  # this is the role python file we will exec
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

    # RPC wrappers

    def get_file(self, sock, path, **opts):
        msg = {'type': 'get_file', 'path': path}
        msg.update(opts)
        return self.do_rpc(sock, msg)

    def syncdir_get_file(self, sock, path):
        msg = {'type': 'syncdir_get_file', 'path': path}
        return self.do_rpc(sock, msg)

    def syncdir_scandir(self, sock, path, exclude=None):
        msg = {'type': 'syncdir_scandir', 'path': path, 'exclude': exclude}
        return self.do_rpc(sock, msg)

    def server_shell(self, sock, cmds, **kwds):
        msg = {'type': 'server_shell', 'cmds': cmds, 'kwds': kwds}
        return self.do_rpc(sock, msg)

    # / RPC wrappers

    def _pinger(self, q):
        # keep our long-lived socket alive, ping every N seconds and update
        # facts periodically, if we don't get a pong back in 1.5x the ping
        # interval, consider the socket stuck and exit - this will cause the
        # handle function to exit and the serve_forever loop to re-connect.
        last_facts = time.time()
        while 1:
            now = time.time()
            msg = {'type': 'ping'}
            if now - last_facts > FACTS_INTERVAL:
                # re-send facts every ~1m
                msg['id'] = self.id
                msg['facts'] = get_facts()
                last_facts = now

            self.send_msg(q, msg)
            time.sleep(PING_INTERVAL)

            # if no pong back, break
            #
            # this could cause issues if we're sending very large files over
            # slow connections and the pong could be behind a lot of other
            # messages...
            if (self._last_pong - now) > (PING_INTERVAL * 1.5):
                log_error('MISSING PONG', self._last_pong - now)
                break

    def handle(self, sock, addr):
        # Connection main loop, handle messages received from the server and
        # create two threads; one that writes messages back to the socket from
        # a Queue, and another that pings the server every N seconds
        log(f'Connection established {addr[0]}:{addr[1]}')
        q = Queue()
        g = gevent.spawn(self._writer, sock, q)

        p = gevent.spawn(self._pinger, q)
        self.send_msg(q, {'type': 'identify', 'id': self.id, 'facts': get_facts()})

        try:
            while 1:
                try:
                    # if writer / pinger dead, break and eventually close the
                    # socket...
                    if g.dead or p.dead:
                        break

                    msg = self.recv_msg(sock)
                    self.handle_msg(msg, q)
                except OSError:
                    log(f'Connection lost {addr[0]}:{addr[1]}')
                    break
        finally:
            g.kill()
            p.kill()
            sock.close()

    def serve_forever(self):
        # Connect loop, connect to the server creating a socket and pass that
        # to handle - If handle raises or exits, take a short break and
        # reconnect.
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
            finally:
                if sock:
                    sock.close()
                    sock = None

            time.sleep(3)

    def run(self, msg):
        # Run a single message and return result - used by the cli for
        # apply/hosts/etc
        sock = self.connect()
        self.send_msg(sock, msg)

        start = time.time()
        while 1:
            try:
                msg = self.recv_msg(sock, timeout=5)
                if msg['type'] != 'pong':
                    return msg
                log(f'Working {int(time.time()-start):} seconds ...', end='\r')
            except ConnectionTimeout:
                self.send_msg(sock, {'type': 'ping'})

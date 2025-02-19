import os
import os.path
import socket
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
    # The client process, we connect to the server, identify with id/facts,
    # start a ping process to keep our connection alive and periodically update
    # facts, and then wait for commands.

    def __init__(self, addr, keyroot=os.getcwd(), id=None, path=''):
        self.futures = {}
        self.keyroot = keyroot

        self.addr = addr
        self.id = id
        self.path = path

        self._last_pong = time.time()

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = self.wrap_socket(sock)
        sock.connect(self.addr)
        return sock

    def handle_pong(self, msg, q):
        self._last_pong = time.time()

    def handle_run(self, msg, q):
        # Run a role on this client and report back results of each command
        start = time.time()

        # these closures capture the Queue that we write the rpc response to
        # during the run for these functions which get injected into the global
        # namespace for the role python file being exec'd
        def get_file(path, **opts):
            msg = {'type': 'get_file', 'path': path}
            msg.update(opts)
            res = self.do_rpc(msg, q)
            assert not res.get('error'), res['error']
            return res

        def syncdir_get_file(path):
            msg = {'type': 'syncdir_get_file', 'path': path}
            res = self.do_rpc(msg, q)
            assert not res.get('error'), res['error']
            return res

        def syncdir_scandir(path, exclude=None):
            msg = {'type': 'syncdir_scandir', 'path': path, 'exclude': exclude}
            res = self.do_rpc(msg, q)
            assert not res.get('error'), res['error']
            return res['data']

        def server_shell(cmds, **kwds):
            msg = {'type': 'server_shell', 'cmds': cmds, 'kwds': kwds}
            res = self.do_rpc(msg, q)
            assert not res.get('error'), res['error']
            return res['data']

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
        q.put(msg)

        rc = sum(_['rc'] for _ in results)
        log(f'Run {msg["context"]["id"]} {msg["context"]["role"]} {rc} {msg["result"]["elapsed"]:.6f}')

    def _pinger(self, q):
        # Keep our long-lived socket alive, ping every N seconds and update
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

            q.put(msg)
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
        # Connection message loop, handle messages received from the server and
        # create two threads; one that writes messages back to the socket from
        # a Queue, and another that pings the server every N seconds
        log(f'Connection established {addr[0]}:{addr[1]}')

        q = Queue()
        g = gevent.spawn(self._writer, q, sock)

        p = gevent.spawn(self._pinger, q)
        q.put({'type': 'identify', 'id': self.id, 'facts': get_facts()})

        try:
            while 1:
                try:
                    # if writer / pinger dead, break and eventually close the
                    # socket...
                    if g.dead or p.dead:
                        break

                    msg = self.recv_msg(sock)
                    if not msg:
                        break

                    self.handle_msg(msg, q)
                except OSError as e:
                    log_error(f'Connection lost {addr[0]}:{addr[1]} exc:{e}')
                    break
        finally:
            log(f'Connection lost {addr[0]}:{addr[1]}')
            [_.kill() for _ in (g, p) if not _.dead]
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

            time.sleep(3)

    def run(self, msg):
        # Run a single message and return result - used by the cli for
        # apply/hosts/etc
        #
        # I don't use a Queue / greenlet writer here since there is only the
        # current thread interacting with this socket...

        sock = self.connect()
        self.send_msg(sock, msg)

        start = time.time()
        while 1:
            try:
                msg = self.recv_msg(sock, timeout=5)
                if not msg:
                    log_error('Server unexpectedly disconnected...')
                    break
                if msg['type'] != 'pong':
                    return msg
                log(f'Working {int(time.time()-start):} seconds ...', end='\r')
            except ConnectionTimeout:
                self.send_msg(sock, {'type': 'ping'})

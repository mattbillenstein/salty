import struct
import time
import uuid
from queue import Queue

import gevent
import msgpack
from gevent.event import AsyncResult

from .compat import get_facts
from .util import log, log_error

class ConnectionTimeout(Exception):
    pass
CONNECTION_TIMEOUT = ConnectionTimeout('Connection timeout')
SOCKET_TIMEOUT = 30

def recvall(sock, size):
    # reading from a socket, there is no guarantee how much data you might get;
    # it's a stream although if you get no data, the socket is disconnected.
    # Loop until we get size bytes...
    data = b''
    while 1:
        newdata = sock.read(size - len(data))
        if not newdata:
            raise ConnectionError('Socket dead')
        data += newdata
        if len(data) == size:
            break
    return data

class Reactor:

    def do_rpc(self, sock, msg):
        msg['future_id'] = id = str(uuid.uuid4())
        self.futures[id] = ar = AsyncResult()
        self.send_msg(sock, msg)
        return ar.get()

    def send_msg(self, sock, msg):
        data = msgpack.packb(msg)
        data = struct.pack('!I', len(data)) + data
        if isinstance(sock, Queue):
            sock.put(data)
            return len(data)
        with gevent.Timeout(SOCKET_TIMEOUT, CONNECTION_TIMEOUT):
            sock.sendall(data)

    def recv_msg(self, sock, timeout=SOCKET_TIMEOUT):
        with gevent.Timeout(timeout, CONNECTION_TIMEOUT):
            data = recvall(sock, 4)
            size = struct.unpack('!I', data)[0]
            if size > 500_000_000:
                raise ConnectionError('Message too big')

            data = recvall(sock, size)
            return msgpack.unpackb(data)

    def _writer(self, sock, q):
        while 1:
            msg = q.get()
            with gevent.Timeout(SOCKET_TIMEOUT, CONNECTION_TIMEOUT):
                sock.sendall(msg)

    def _pinger(self, q):
        last_facts = time.time()
        while 1:
            now = time.time()
            msg = {'type': 'ping'}
            if now - last_facts > 60.0:
                # re-send facts every ~1m
                msg['id'] = self.id
                msg['facts'] = get_facts()
            self.send_msg(q, msg)
            time.sleep(5)

            # if no pong back, break
            if (self._last_pong - now) > 6:
                log_error('MISSING PONG', self._last_pong - now)
                break

    def handle_future(self, msg, q):
        ar = self.futures.pop(msg['future_id'], None)
        if ar:
            ar.set(msg)

    def handle_msg(self, msg, q):
        method = getattr(self, 'handle_' + msg['type'], None)
        if method:
            gevent.spawn(method, msg, q)
        else:
            msg['error'] = f"Method {msg['type']} not found"
            self.send_msg(q, msg)
            log_error(f'Unhandled message: {msg}')

    def handle(self, sock, addr, is_client=False):
        log(f'Connection established {addr[0]}:{addr[1]}')
        client_id = None
        q = Queue()
        g = gevent.spawn(self._writer, sock, q)

        p = None
        if is_client:
            p = gevent.spawn(self._pinger, q)
            self.send_msg(q, {'type': 'identify', 'id': self.id, 'facts': get_facts()})

        try:
            while 1:
                try:
                    # if writer dead, break and eventually close the socket...
                    if g.dead or (p and p.dead):
                        break

                    msg = self.recv_msg(sock)
                    if msg['type'] == 'identify':
                        client_id = msg['id']
                        log(f'id:{client_id} facts:{msg["facts"]}')
                        self.clients[client_id] = q
                        self.facts[client_id] = msg['facts']
                    else:
                        self.handle_msg(msg, q)
                except OSError:
                    log(f'Connection lost {addr[0]}:{addr[1]}')
                    break
        finally:
            if not is_client and self.clients.get(client_id) is q:
                self.clients.pop(client_id)
            g.kill()
            if p:
                p.kill()
            sock.close()

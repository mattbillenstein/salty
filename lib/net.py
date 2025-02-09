import os.path
import ssl
import struct
import threading
import time
import uuid
from queue import Queue

import msgpack

from .compat import get_facts
from .util import log, log_error, spawn_thread

PING_INTERVAL = 10.0
FACTS_INTERVAL = 60.0

class AsyncResult:
    def __init__(self):
        self.evt = threading.Event()
        self.value = None

    def set(self, value):
        self.value = value
        self.evt.set()

    def get(self):
        self.evt.wait()
        return self.value

def recvall(sock, size):
    # reading from a socket, there is no guarantee how much data you might get;
    # it's a stream although if you get no data, the socket is disconnected.
    # Loop until we get size bytes...
    data = b''
    while 1:
        newdata = sock.recv(size - len(data))
        if not newdata:
            return b''
        data += newdata
        if len(data) == size:
            break
    return data

class Reactor:

    def wrap_socket(self, sock, server_side=False):
        prot = ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
        ctx = ssl.SSLContext(prot)
        ctx.check_hostname = False
        ctx.load_cert_chain(
            certfile=os.path.join(self.keyroot, 'cert.pem'),
            keyfile=os.path.join(self.keyroot, 'key.pem'),
        )
        ctx.load_verify_locations(os.path.join(self.keyroot, 'cert.pem'))
        sock = ctx.wrap_socket(sock, server_side=server_side)
        return sock

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
        sock.sendall(data)

    def recv_msg(self, sock):
        data = recvall(sock, 4)
        if not data:
            return None
        size = struct.unpack('!I', data)[0]
        if size > 500_000_000:
            raise Exception('Message too big')

        data = recvall(sock, size)
        return msgpack.unpackb(data)

    def _writer(self, sock, q):
        while 1:
            msg = q.get()
            sock.sendall(msg)

    def _pinger(self, q):
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
            self.send_msg(q, msg)
            time.sleep(PING_INTERVAL)

            # if no pong back, break
            if (self._last_pong - now) > (PING_INTERVAL * 1.5):
                log_error('MISSING PONG', self._last_pong - now)
                break

    def handle_future(self, msg, q):
        ar = self.futures.pop(msg['future_id'], None)
        if ar:
            ar.set(msg)

    def handle_msg(self, msg, q):
        method = getattr(self, 'handle_' + msg['type'], None)
        if method:
            spawn_thread(method, (msg, q))
        else:
            msg['error'] = f"Method {msg['type']} not found"
            self.send_msg(q, msg)
            log_error(f'Unhandled message: {msg}')

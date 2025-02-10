import os.path
import queue
import select
import socket
import ssl
import struct
import threading
import time
import traceback
import uuid

import msgpack

from .compat import get_facts
from .util import log, log_error, spawn_thread

def wrap_socket(sock, keyroot, server_side=False):
    return sock
    proto = ssl.PROTOCOL_TLS_CLIENT
    if server_side:
        proto = ssl.PROTOCOL_TLS_SERVER
    ctx = ssl.SSLContext(proto)
    ctx.check_hostname = False
    ctx.load_cert_chain(
        certfile=os.path.join(keyroot, 'cert.pem'),
        keyfile=os.path.join(keyroot, 'key.pem'),
    )
    ctx.load_verify_locations(os.path.join(keyroot, 'cert.pem'))
    return ctx.wrap_socket(sock, server_side=server_side)

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

class Socket:
    # send/recv full messages over a socket, reading is done on the main
    # thread, writing on another...

    def __init__(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
        self.sock = sock
        self.writeq = queue.Queue()
        self._running = True
        self.writet = spawn_thread(self._writer)

    def send_msg(self, msg):
        data = msgpack.packb(msg)
        data = struct.pack('!I', len(data)) + data
        self.writeq.put(data)

    def recv_msg(self):
        start = time.time()
        data = self._recvall(4)
        if not data:
            return None
        size = struct.unpack('!I', data)[0]
        if size > 500_000_000:
            raise Exception('Message too big')

        data = self._recvall(size)
        if not data:
            return None
        msg = msgpack.unpackb(data)
        print('recv_msg', msg['type'], time.time() - start)
        return msg

    def is_alive(self):
        return self.writet.is_alive()

    def close(self):
        self._running = False
        self.writet.join()
        self.sock.close()

    def fileno(self):
        return self.sock.fileno()

    def _writer(self):
        while self._running:
            try:
                msg = self.writeq.get(timeout=1.0)
                start = time.time()
                self._sendall(msg)
                log('Socket send', len(msg), time.time() - start, repr(msg[:50]))
            except queue.Empty:
                pass

    def _recvall(self, size):
        # reading from a socket, there is no guarantee how much data you might get;
        # it's a stream although if you get no data, the socket is disconnected.
        # Loop until we get size bytes...
        data = b''
        while 1:
            newdata = self.sock.recv(size - len(data))
            if not newdata:
                return b''
            data += newdata
            if len(data) == size:
                break
        return data

    def _sendall(self, data):
        self.sock.sendall(data)

class Reactor:
    # Simple server/client mixin for common stuff

    def do_rpc(self, sock, msg):
        msg['future_id'] = id = str(uuid.uuid4())
        self.futures[id] = ar = AsyncResult()
        sock.send_msg(msg)
        return ar.get()

    def handle_future(self, msg, q):
        ar = self.futures.pop(msg['future_id'], None)
        if ar:
            ar.set(msg)

    def handle_msg(self, msg, sock):
        method = getattr(self, 'handle_' + msg['type'], None)
        if method:
            spawn_thread(method, (msg, sock))
        else:
            msg['error'] = f"Method {msg['type']} not found"
            sock.send_msg(msg)
            log_error(f'Unhandled message: {msg}')

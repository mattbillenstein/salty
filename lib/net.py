import struct
import uuid
from queue import Queue

import gevent
import msgpack
from gevent.event import AsyncResult

from .util import log_error

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
    # Reading/writing sockets and futures/rpc mixin, subclasses read and write
    # whole messages which are just dicts {'type': '<type>', ...payload...}

    def send_msg(self, sock, msg):
        # encode messages as 4-bytes message size (up to 4GiB) followed by a
        # msgpack blob
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
                # FIXME, this is only really a limit for big file copies,
                # implement a chunked protocol for get_file / syncdir_get_file
                # so we don't have to have the entire file in RAM... Perhaps
                # 64MB chunks.
                raise ConnectionError('Message too big')

            data = recvall(sock, size)
            return msgpack.unpackb(data)

    def _writer(self, sock, q):
        # write to a socket in a separate greenlet reading from queue - this is
        # mainly for message framing.
        while 1:
            msg = q.get()
            with gevent.Timeout(SOCKET_TIMEOUT, CONNECTION_TIMEOUT):
                sock.sendall(msg)

    def do_rpc(self, sock, msg):
        # Register a future using AsyncResult, send the request, and block
        # until it's set
        msg['future_id'] = id = str(uuid.uuid4())
        self.futures[id] = ar = AsyncResult()
        self.send_msg(sock, msg)
        return ar.get()

    def handle_future(self, msg, q):
        # Pull AsyncResult from registry and set it
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

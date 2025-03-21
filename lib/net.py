import os
import os.path
import struct
import ssl
import uuid

import gevent
import msgpack
from gevent.event import AsyncResult

from . import crypto
from .util import log_error

class ConnectionTimeout(ConnectionError):
    pass

CONNECTION_TIMEOUT = ConnectionTimeout('Connection timeout')
SOCKET_TIMEOUT = 30

def recvall(sock, size):
    # reading from a socket, there is no guarantee how much data you might get;
    # it's a stream although if you get no data, the socket is disconnected.
    # Loop until we get size bytes...
    data = b''
    while 1:
        newdata = sock.recv(size - len(data))
        if not newdata:
            # Connection lost, return empty data
            return b''
        data += newdata
        if len(data) == size:
            break
    return data

class MsgMixin:
    # Reading/writing sockets and futures/rpc mixin
    #
    # Subclasses read and write whole messages using recv_msg/send_msgwhich are
    # just dicts:
    #
    #     {'type': '<type>', ...payload...}
    #
    # And encoded on the wire using msgpack.
    #
    # Writing to sockets is generally done in a dedicated greenlet reading from
    # a Queue so we have proper message framing - ie, we're not mixing messages
    # on the wire.

    def xxx_wrap_socket(self, sock, server_side=False):
        # Python ssl will only recv 16kb at a time with non-blocking sockets
        # while holding the GIL, there is a PR to improve this, but who knows
        # when it'll get merged. It makes reading large files over these
        # sockets very very slow...
        #
        # https://github.com/python/cpython/pull/31492
        proto = ssl.PROTOCOL_TLS_CLIENT
        if server_side:
            proto = ssl.PROTOCOL_TLS_SERVER
        ctx = ssl.SSLContext(proto)
        ctx.check_hostname = False
        ctx.load_cert_chain(
            certfile=os.path.join(self.keyroot, 'cert.pem'),
            keyfile=os.path.join(self.keyroot, 'key.pem'),
        )
        ctx.load_verify_locations(os.path.join(self.keyroot, 'cert.pem'))
        return ctx.wrap_socket(sock, server_side=server_side)

    def wrap_socket(self, sock, server_side=False):
        with open(os.path.join(self.keyroot, 'crypto.pass')) as f:
            password = f.read().strip()
        return EncryptedSocket(sock, password)

    def send_msg(self, sock, msg):
        # encode messages as 4-bytes message size (up to 4GiB) followed by a
        # msgpack blob
        data = msgpack.packb(msg)
        data = struct.pack('!I', len(data)) + data
        with gevent.Timeout(SOCKET_TIMEOUT, CONNECTION_TIMEOUT):
            sock.sendall(data)

    def recv_msg(self, sock, timeout=SOCKET_TIMEOUT):
        with gevent.Timeout(timeout, CONNECTION_TIMEOUT):
            data = recvall(sock, 4)
            if not data:
                return None

            size = struct.unpack('!I', data)[0]
            data = recvall(sock, size)
            if not data:
                return None

            return msgpack.unpackb(data)

    def _writer(self, q, sock):
        # get from q and write to sock in a separate greenlet - mainly for
        # message framing...
        while 1:
            msg = q.get()
            if not msg:
                return
            with gevent.Timeout(SOCKET_TIMEOUT, CONNECTION_TIMEOUT):
                self.send_msg(sock, msg)

    def _reader(self, sock, q):
        # read from sock and put to q in a separate greenlet
        while 1:
            with gevent.Timeout(SOCKET_TIMEOUT, CONNECTION_TIMEOUT):
                msg = self.recv_msg(sock)
            q.put(msg)
            if not msg:
                # exit after put so we wake any readers who can also exit
                return

    def do_rpc(self, msg, q, futures=None):
        # Register a future using AsyncResult, send the request, and block
        # until it's set
        if futures is None:
            futures = self.futures

        msg['future_id'] = id = str(uuid.uuid4())
        futures[id] = ar = AsyncResult()
        q.put(msg)
        return ar.get()

    def handle_future(self, msg, q, futures=None):
        # Pull AsyncResult from registry and set it
        if futures is None:
            futures = self.futures

        ar = futures.pop(msg['future_id'], None)
        if ar:
            ar.set(msg)
        else:
            log_error(f'Unhandled future: {msg["future_id"]}')

    def handle_msg(self, msg, q, futures=None):
        if msg['type'] == 'future':
            return self.handle_future(msg, q, futures)

        method = getattr(self, 'handle_' + msg['type'], None)
        if method:
            gevent.spawn(method, msg, q)
        else:
            log_error(f'Unhandled message: {msg}')
            msg['error'] = f"Method {msg['type']} not found"
            q.put(msg)


class EncryptedSocket:
    def __init__(self, sock, password):
        self.sock = sock
        self.buf = b''
        self.box = crypto.make_secretbox(password)

        self.connect = self.sock.connect
        self.close = self.sock.close
        self.getpeername = self.sock.getpeername

    def sendall(self, data):
        data = self.box.encrypt(data)
        data = struct.pack('!I', len(data)) + data
        self.sock.sendall(data)

    def recv(self, size):
        if len(self.buf) >= size:
            data = self.buf[:size]
            self.buf = self.buf[size:]
            return data

        data = recvall(self.sock, 4)
        if not data:
            return None

        esize = struct.unpack('!I', data)[0]
        data = recvall(self.sock, esize)
        if not data:
            return None

        self.buf += self.box.decrypt(data)
        data = self.buf[:size]
        self.buf = self.buf[size:]
        return data

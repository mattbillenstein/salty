import os
import os.path
import socket
import subprocess
import time
import traceback
from queue import Queue

import gevent

from lib import crypto, operators
from lib.net import MsgMixin
from lib.util import elapsed, get_crypto_pass, hash_data, log, log_error

class ClientProc(MsgMixin):
    # Terminate TLS for this client and handle file/shell rpcs - proxy
    # everything else to the server process.

    def __init__(self, client_fd, server_fd, keyroot, fileroot):
        self.futures = {}
        self.keyroot = keyroot
        self.fileroot = fileroot

        self.crypto_pass = get_crypto_pass(self.keyroot)

        # We are invoked via subprocess.run taking fds from the cli - turn them
        # into sockets...
        client_sock = socket.fromfd(client_fd, socket.AF_INET, socket.SOCK_STREAM)

        # And communication with the client is over tls sockets with keys from
        # keyroot, wrap the socket
        self.client_sock = self.wrap_socket(client_sock, server_side=True)

        # Connection to the server is on the same machine, no tls here
        self.server_sock = socket.fromfd(server_fd, socket.AF_INET, socket.SOCK_STREAM)

        # Write queues for each socket
        self.client_q = Queue()
        self.server_q = Queue()

    def serve_forever(self):
        addr = self.client_sock.getpeername()
        pid = os.getpid()

        log(f'ClientProc serve_forever {addr[0]}:{addr[1]} pid:{pid}')

        # reader server_sock -> client_q
        s2c = gevent.spawn(self._reader, self.server_sock, self.client_q)

        # writer client_q -> client_sock
        c2c = gevent.spawn(self._writer, self.client_q, self.client_sock)

        # writer server_q -> server_sock
        s2s = gevent.spawn(self._writer, self.server_q, self.server_sock)

        threads = (s2c, c2c, s2s)

        # and in this thread,
        # reader client_sock -> client_q or server_sock

        try:
            while 1:
                try:
                    if any(_.dead for _ in threads):
                        break

                    msg = self.recv_msg(self.client_sock)
                    if not msg:
                        break

                    method = getattr(self, 'handle_' + msg['type'], None)
                    if method:
                        # if we have a handler for this type, run it
                        gevent.spawn(method, msg, self.client_q)
                    else:
                        # otherwise, let the server handle it
                        self.server_q.put(msg)

                except OSError as e:
                    log_error(f'Connection lost {addr[0]}:{addr[1]} pid:{pid} exc:{e}')
                    break
        finally:
            log(f'Connection lost {addr[0]}:{addr[1]} pid:{pid}')
            [_.kill() for _ in threads if not _.dead]
            self.client_sock.close()
            self.server_sock.close()

    def handle_future(self, msg, q):
        # Override base class method - if we get a message we don't have a
        # future for, send that msg to server.
        ar = self.futures.pop(msg['future_id'], None)
        if ar:
            # our future, set it
            ar.set(msg)
        else:
            # server future
            self.server_q.put(msg)

    def handle_get_file(self, msg, q):
        # serve files from <fileroot>/files
        path = os.path.join(self.fileroot, 'files', msg['path'])

        # automatically decrypt files ending with .enc
        if os.path.exists(path + '.enc'):
            path += '.enc'

        msg['type'] = 'future'

        try:
            with open(path, 'rb') as f:
                data = f.read()

            if path.endswith('.enc'):
                data = crypto.decrypt(data, self.crypto_pass)

            hash = hash_data(data)
            if msg.get('hash') != hash:
                msg['data'] = data
                msg['hash'] = hash

            msg['mode'] = os.stat(path).st_mode & 0o777
        except Exception:
            log_error('Exception handling msg in handle_get_file:', msg)
            tb = traceback.format_exc().strip()
            log(tb)
            msg['error'] = tb

        q.put(msg)

    def handle_syncdir_get_file(self, msg, q):
        # syncdir get_file uses absolute paths and does no decryption - this is
        # part of the interface for a home-grown rsync
        msg['type'] = 'future'

        try:
            msg['size'] = size = os.stat(msg['path']).st_size
            offset = msg.get('offset', 0)
            with open(msg['path'], 'rb') as f:
                if offset:
                    f.seek(offset)
                data = f.read(100*1024*1024)
            msg['data'] = data
        except Exception:
            log_error('Exception handling msg in handle_syncdir_get_file:', msg)
            tb = traceback.format_exc().strip()
            log(tb)
            msg['error'] = tb

        q.put(msg)

    def handle_syncdir_scandir(self, msg, q):
        # recursively scan a local path and return all found file/dir metadata
        msg['type'] = 'future'

        try:
            msg['data'] = operators.syncdir_scandir_local(msg['path'], exclude=msg.get('exclude'))
        except Exception:
            log_error('Exception handling msg in handle_syncdir_scandir:', msg)
            tb = traceback.format_exc().strip()
            log(tb)
            msg['error'] = tb

        q.put(msg)

    def handle_server_shell(self, msg, q):
        # run a shell command and return output and return code
        msg['type'] = 'future'

        try:
            start = time.time()
            p = subprocess.run(msg['cmds'], shell=True, capture_output=True, **msg['kwds'])
            msg['data'] = {
                'rc': p.returncode,
                'output': p.stdout.decode('utf8') + '\n' + p.stderr.decode('utf8'),
                'elapsed': elapsed(start),
            }
        except Exception:
            log_error('Exception handling msg in handle_server_shell:', msg)
            tb = traceback.format_exc().strip()
            log(tb)
            msg['error'] = tb

        q.put(msg)

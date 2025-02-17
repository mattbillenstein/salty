import fnmatch
import os
import os.path
import socket
import subprocess
import sys
import time
import traceback
from collections import defaultdict
from queue import Queue

import gevent
import gevent.server
#import gipc
import msgpack

from lib import crypto, operators
from lib.net import MsgMixin
from lib.util import elapsed, get_crypto_pass, get_meta, hash_data, log, log_error


def client_proc(sock_fd, server_q, keyroot, fileroot):
    print('client_proc start', os.getpid())
    server_q = socket.fromfd(sock_fd, socket.AF_INET, socket.SOCK_STREAM)

    while 1:
        server_q.send(b'hi there ' + str(time.time()).encode('utf8'))

    server_conn.send({'hi': 'there'})
    ClientProc(sock, server_q, keyroot, fileroot).serve_forever()


class SaltyServer(gevent.server.StreamServer, MsgMixin):
    def __init__(self, *args, **kwargs):
        self.clients = {}
        self.facts = {}
        self.futures = {}

        self.fileroot = kwargs.pop('fileroot', os.getcwd())
        self.keyroot = kwargs.pop('keyroot', os.getcwd())
        self.crypto_pass = get_crypto_pass(self.keyroot)

        print('Server init', args, kwargs)

        super().__init__(*args, **kwargs)

    def handle(self, sock, addr):
        log(f'Connection established {addr[0]}:{addr[1]}')

        #client_q, server_q = gipc.pipe(duplex=True)
        #client_q, server_q = socket.socketpair()

        # create subprocess, args here are pickled to the other process
        #p = gipc.start_process(target=client_proc, args=(sock.fileno(), server_q.fileno(), self.keyroot, self.fileroot), daemon=True)

        #import multiprocessing
        #client_q, server_q = multiprocessing.Pipe(True)
        #p = multiprocessing.Process(target=client_proc, args=(sock.fileno(), server_q, self.keyroot, self.fileroot), daemon=True)
        #p.start()

        client_q, server_q = socket.socketpair()
        path = os.path.abspath(os.path.dirname(__file__))
        exe = os.path.join(path, 'client_proc.py')
        args = [str(sock.fileno()), str(server_q.fileno()), self.keyroot, self.fileroot]
        p = subprocess.Popen([exe] + args, pass_fds=(sock.fileno(), server_q.fileno()))

        while not p.pid:
            time.sleep(0.01)

        print(p, p.pid, os.getpid())

        #sock.close()

        client_id = None
        #client_q = Queue()
        #g = gevent.spawn(self._writer, client_q, sock)

        try:
            while 1:
                try:
                    # if writer dead, break and eventually close the socket...
                    #if g.dead:
                    #    break

                    msg = self.recv_msg(client_q)
                    print('Server got', msg)
                    if msg['type'] == 'identify':
                        client_id = msg['id']
                        log(f'id:{client_id} facts:{msg["facts"]}')
                        self.clients[client_id] = client_q
                        self.facts[client_id] = msg['facts']
                    else:
                        self.handle_msg(msg, client_q)
                except OSError as e:
                    log(f'Connection lost {addr[0]}:{addr[1]} {e}')
                    break
        finally:
            if self.clients.get(client_id) is client_q:
                self.clients.pop(client_id)
            p.kill()
            #g.kill()
            #client_q.close()

    def handle_ping(self, msg, q):
        if facts := msg.get('facts'):
            self.facts[msg['id']] = facts
        self.send_msg(q, {'type': 'pong'})

    def handle_hosts(self, msg, q):
        meta = get_meta(self.fileroot, self.crypto_pass)
        hosts = self.get_hosts(meta)
        msg['hosts'] = {k: v for k, v in hosts.items() if v['facts']}
        self.send_msg(q, msg)

    def get_hosts(self, meta):
        # Return host metadata / facts for all available hosts
        hosts = {}
        for cluster, servers in meta['hosts'].items():
            for id, data in servers.items():
                ids = [id]

                # if not a direct match, probably a fnmatch wildcard, expand
                # wildcard against hosts currently in facts...
                if any(_ in id for _ in '*![]?'):
                    ids = fnmatch.filter(self.facts, id)

                for id in ids:
                    v = dict(data)
                    v['cluster'] = cluster
                    v['facts'] = self.facts.get(id)

                    # vars precedence - env, cluster, host - save off host vars
                    # first and apply last...
                    vars = v.get('vars', {})
                    v['vars'] = {}
                    v['vars'].update(meta['envs'][v['env']])
                    v['vars'].update(meta['clusters'][cluster])
                    v['vars'].update(vars)
                    hosts[id] = v

        return hosts

    def handle_apply(self, msg, q):
        print('handle_apply', msg)
        # Apply roles to all connected hosts and return status on everything
        # that was run. This does a scatter/gather on each host for each role
        # executed in order.
        start = time.time()
        results = defaultdict(dict)
        msg_result = {'type': 'apply_result', 'results': results}

        try:
            target = msg.get('target')
            target_cluster = None
            if target and target.startswith('cluster:'):
                target_cluster = target.split(':')[1]
                target = None

            meta = get_meta(self.fileroot, self.crypto_pass)

            hosts = self.get_hosts(meta)

            for id in list(hosts):
                v = hosts[id]
                # skip disconnected / non-existing hosts, but return error
                # if target is cluster
                if v['facts'] is None:
                    if target_cluster and target_cluster == v['cluster']:
                        if not v.get('ignore_missing', False):
                            results[id][''] = {'results': [{'rc': 1, 'cmd': '...host missing...', 'elapsed': 0.0, 'changed': False}], 'elapsed': 0.0}
                    del hosts[id]

            # unwind cluster -> id in hosts and apply facts/envs/clusters
            # roles to apply, if empty, apply all host roles
            roles = msg.get('roles', [])
            # roles to skip unless given explictely
            skip = [_ for _ in msg.get('skip', []) if _ not in roles]

            context = {k: v for k, v in msg.items() if k not in ('type', 'target', 'roles', 'skip')}

            for id, q2 in self.clients.items():
                if id not in hosts:
                    log_error(f'Apply missing host {id} in metadata')
                    continue

                if target_cluster and hosts[id]['cluster'] != target_cluster:
                    continue

                for role in hosts[id]['roles']:
                    if not os.path.isfile(os.path.join(self.fileroot, 'roles', f'{role}.py')):
                        # roles are sometimes just tags, just silently ignore
                        # missing role .py files
                        # results[id][role] = {'results': [{'rc': 1, 'cmd': '...role missing...', 'elapsed': 0.0, 'changed': False}], 'elapsed': 0.0}
                        continue

                    if (roles and role not in roles) or role in skip:
                        results[id][role] = {'results': [{'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}], 'elapsed': 0.0}
                        continue

                    # target here can be glob by id (p-*.foo.dev)
                    if target and not fnmatch.fnmatch(id, target):
                        results[id][role] = {'results': [{'rc': 0, 'cmd': '...host skipped...', 'elapsed': 0.0, 'changed': False}], 'elapsed': 0.0}
                        continue

                    with open(os.path.join(self.fileroot, 'roles', f'{role}.py')) as f:
                        content = f.read()

                    ctx = {'id': id, 'role': role, 'hosts': hosts, 'me': hosts[id], 'bootstrap': False}
                    ctx.update(context)
                    msg = {'type': 'run', 'content': content, 'context': ctx}
                    results[id][role] = (q2, msg)

            # scatter by host, then collect - roles must be run sequentially
            def dispatch(host_roles):
                for role, tup in list(host_roles.items()):
                    if not isinstance(tup, dict):
                        x = tup[-1]['context']
                        t = time.time()
                        host_roles[role] = m = self.do_rpc(*tup)['result']
                        rc = sum(_['rc'] for _ in m['results'])
                        log('RPC', x['id'], x['role'], rc, f'{elapsed(t):.6f}')

            greenlets = []
            for id, host_roles in results.items():
                g = gevent.spawn(dispatch, host_roles)
                greenlets.append(g)

            gevent.wait(greenlets)

        except Exception:
            log_error('Exception handling msg in handle_apply:', msg)
            tb = traceback.format_exc().strip()
            print(tb)
            msg_result['error'] = tb

        msg_result['elapsed'] = elapsed(start)
        self.send_msg(q, msg_result)


class ClientProc(MsgMixin):

    # Do heavy lifting for a client connection in another process, proxy
    # unhandled messages to the actual server.

    def __init__(self, client_sock, server_sock, keyroot, fileroot):
        self.futures = {}
        self.keyroot = keyroot
        self.fileroot = fileroot
        self.client_sock = self.wrap_socket(client_sock, server_side=True)
        self.server_sock = server_sock

    def serve_forever(self):
        log('ClientProc serve_forever')
        client_q = Queue()
        server_q = Queue()
        self.server_q = server_q

        # reader server_sock -> client_q
        s2c = gevent.spawn(self._reader, self.server_sock, client_q)

        # writer client_q -> client_sock
        c2c = gevent.spawn(self._writer, client_q, self.client_sock)

        # writer server_q -> server_sock
        s2s = gevent.spawn(self._writer, server_q, self.server_sock)

        threads = (s2c, c2c, s2s)

        log('ClientProc threads', threads)

        # and in this thread,
        # reader client_sock -> client_q or server_sock

        try:
            while 1:
                try:
                    if any(_.dead for _ in threads):
                        print('read/writer dead')
                        break

                    msg = self.recv_msg(self.client_sock)
                    print('ClientProc got', msg)
                    method = getattr(self, 'handle_' + msg['type'], None)
                    if method:
                        gevent.spawn(method, msg, client_q)
                    else:
                        server_q.put(msg)
                except OSError:
                    addr = self.client_sock.getpeername()
                    log(f'Connection lost {addr[0]}:{addr[1]}')
                    print(traceback.format_exc())
                    break
                except OSError as e:
                    log(f'OSError: {e}')
                    print(traceback.format_exc())
                    break
        finally:
            [_.kill() for _ in threads]
            self.client_sock.close()
            self.server_sock.close()

    def handle_future(self, msg, q):
        # Pull AsyncResult from registry and set it
        ar = self.futures.pop(msg['future_id'], None)
        if ar:
            ar.set(msg)
        else:
            # proxy to server
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
            print(tb)
            msg['error'] = tb

        self.send_msg(q, msg)

    def handle_syncdir_get_file(self, msg, q):
        # syncdir get_file uses absolute paths and does no decryption - this is
        # part of the interface for a home-grown rsync
        msg['type'] = 'future'

        try:
            with open(msg['path'], 'rb') as f:
                data = f.read()
            msg['data'] = data
        except Exception:
            log_error('Exception handling msg in handle_syncdir_get_file:', msg)
            tb = traceback.format_exc().strip()
            print(tb)
            msg['error'] = tb

        self.send_msg(q, msg)

    def handle_syncdir_scandir(self, msg, q):
        # recursively scan a local path and return all found file/dir metadata
        msg['type'] = 'future'

        try:
            msg['data'] = operators.syncdir_scandir_local(msg['path'], exclude=msg.get('exclude'))
        except Exception:
            log_error('Exception handling msg in handle_syncdir_scandir:', msg)
            tb = traceback.format_exc().strip()
            print(tb)
            msg['error'] = tb

        self.send_msg(q, msg)

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
            print(tb)
            msg['error'] = tb

        self.send_msg(q, msg)

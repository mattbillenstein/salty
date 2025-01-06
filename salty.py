#!/usr/bin/env python3

import gevent.monkey
gevent.monkey.patch_all()

import fnmatch
import json
import os
import os.path
import platform
import re
import socket
import ssl
import struct
import sys
import time
import traceback
import uuid
from collections import defaultdict
from queue import Queue

import gevent
import gevent.server
import msgpack
from gevent.event import AsyncResult

import crypto
import operators
from compat import get_cpu_count, get_networking, get_mem_gb
from operators import elapsed, hash_data

class ConnectionTimeout(Exception):
    pass
CONNECTION_TIMEOUT = ConnectionTimeout('Connection timeout')
SOCKET_TIMEOUT = 30

def log(*args, **kwargs):
    t = time.time()
    ms = f'{int(t % 1 * 1000):03d}'
    print(time.strftime('%Y-%m-%dT%H:%M:%S.', time.localtime(t)) + ms, *args, **kwargs)
    sys.stdout.flush()

def log_error(*args, **kwargs):
    if sys.stdout.isatty():
        args = [f'\033[1;31m{_}\033[0m' for _ in args]
    log(*args, **kwargs)

def print_error(*args, **kwargs):
    if sys.stdout.isatty():
        args = [f'\033[1;31m{_}\033[0m' for _ in args]
    print(*args, **kwargs)

def pprint(obj):
    print(json.dumps(obj, indent=2))

def get_facts():
    uname = platform.uname()
    return {
        'networking': get_networking(),
        'cpu_count': get_cpu_count(),
        'mem_gb': get_mem_gb(),
        'kernel': uname.system,
        'machine': uname.machine,
    }

def get_meta(fileroot, crypto_pass=None):
    meta = {}
    metapy = os.path.join(fileroot, 'meta.py')
    if os.path.isfile(metapy):
        with open(metapy) as f:
            exec(f.read(), meta)
        meta = {k: v for k, v in meta.items() if k[0] != '_'}
    else:
        for fname in ('hosts', 'envs', 'clusters'):
            with open(os.path.join(fileroot, 'meta', f'{fname}.py')) as f:
                meta[fname] = {}
                exec(f.read(), meta[fname])
                for k in list(meta[fname]):
                    if k.startswith('_'):
                        meta[fname].pop(k)

    if crypto_pass:
        crypto.decrypt_dict(meta, crypto_pass)

    return meta

def get_crypto_pass(keyroot):
    fname = os.path.join(keyroot, 'crypto.pass')
    if os.path.exists(fname):
        with open(fname) as f:
            return f.read().strip()
    return None

class Reactor(object):

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
            data = sock.read(4)
        if not data:
            raise ConnectionError('Socket dead')

        size = struct.unpack('!I', data)[0]
        if size > 500_000_000:
            raise ConnectionError('Message too big')

        data = b''
        with gevent.Timeout(timeout, CONNECTION_TIMEOUT):
            for _ in range(10_000_000):
                # read here seems to yield 16kb at a time...
                data += sock.read(size - len(data))
                if len(data) == size:
                    return msgpack.unpackb(data)

        raise ConnectionError(f'Could not read {size} bytes after {timeout}s')

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
            fh = sock.makefile(mode='b')
            while 1:
                try:
                    # if writer dead, break and eventually close the socket...
                    if g.dead or (p and p.dead):
                        break

                    msg = self.recv_msg(fh)
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

class SaltyServer(gevent.server.StreamServer, Reactor):
    def __init__(self, *args, **kwargs):
        self.clients = {}
        self.facts = {}
        self.futures = {}
        self.fileroot = kwargs.pop('fileroot', os.getcwd())

        keyroot = kwargs.pop('keyroot', os.getcwd())
        kwargs['keyfile'] = os.path.join(keyroot, 'key.pem')
        kwargs['certfile'] = os.path.join(keyroot, 'cert.pem')

        self.crypto_pass = get_crypto_pass(keyroot)

        super().__init__(*args, **kwargs)

    def handle_ping(self, msg, q):
        if facts := msg.get('facts'):
            self.facts[msg['id']] = facts
        self.send_msg(q, {'type': 'pong'})

    def handle_hosts(self, msg, q):
        meta = get_meta(self.fileroot, self.crypto_pass)
        hosts = self.get_hosts(meta)
        msg['hosts'] = {k: v for k, v in hosts.items() if v['facts']}
        self.send_msg(q, msg)

    def handle_get_file(self, msg, q):
        path = os.path.join(self.fileroot, 'files', msg['path'])

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
        msg['type'] = 'future'

        try:
            msg['data'] = operators.syncdir_scandir_local(msg['path'])
        except Exception:
            log_error('Exception handling msg in handle_syncdir_scandir:', msg)
            tb = traceback.format_exc().strip()
            print(tb)
            msg['error'] = tb

        self.send_msg(q, msg)

    def get_hosts(self, meta):
        hosts = {}
        for cluster, servers in meta['hosts'].items():
            for id, data in servers.items():
                ids = [id]

                # if not a direct match, probably a fnmatch wildcard, expand
                # wildcard against hosts currently in facts...
                if any(_ in id for _ in '*![]?'):
                    ids = fnmatch.filter(self.facts, id)
                    log(f'Expanded {id} to {ids}')

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

        except:
            log_error('Exception handling msg in handle_apply:', msg)
            tb = traceback.format_exc().strip()
            print(tb)
            msg_result['error'] = tb

        msg_result['elapsed'] = elapsed(start)
        self.send_msg(q, msg_result)

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
        start = time.time()

        def get_file(path, **opts):
            return self.get_file(q, path, **opts)

        def syncdir_get_file(path):
            return self.syncdir_get_file(q, path)

        def syncdir_scandir(path):
            msg = self.syncdir_scandir(q, path)
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
        )

        msg['type'] = 'future'
        msg['result'] = {'results': results, 'output': '\n'.join(output), 'elapsed': elapsed(start)}
        self.send_msg(q, msg)

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

    def serve_forever(self):
        while 1:
            try:
                sock = self.connect()
                self.handle(sock, self.addr, is_client=True)
            except KeyboardInterrupt:
                break
            except Exception:
                tb = traceback.format_exc().strip()
                log_error('Exception in client serve:\n', tb)
                time.sleep(3)
            finally:
                sock.close()

    def run(self, msg):
        sock = self.connect()
        self.send_msg(sock, msg)

        start = time.time()
        while 1:
            try:
                msg = self.recv_msg(sock, timeout=5)
                if msg['type'] != 'pong':
                    return msg
                log(f'Working {int(time.time()-start):} seconds ...', end='\r')
            except ConnectionTimeout as e:
                self.send_msg(sock, {'type': 'ping'})

def main(*args):
    start = time.time()

    mode = 'help'
    if args:
        mode, args = args[0], args[1:]

    modes = ('facts', 'meta', 'genkey', 'server', 'client', 'cli', 'bootstrap')
    if mode == 'help' or mode not in modes:
        print(f"Usage: ./salty.py ({' | '.join(modes)}) [args]")
        return 0

    # fixme - argparse
    verbose = 0

    # consume salty args, they begin with a -
    opts = {}
    for arg in args:
        if arg.startswith('-v'):
            verbose = arg.count('v')
        elif arg.startswith('--'):
            k, v = arg[2:].split('=', 1)
            opts[k] = v

    # filter run args
    args = [_ for _ in args if not _.startswith('-')]

    if mode == 'facts':
        pprint(get_facts())
        return 0

    if mode == 'meta':
        assert opts['fileroot'], 'Need --fileroot=<path>'
        crypto_pass = None
        if keyroot := opts.get('keyroot'):
            crypto_pass = get_crypto_pass(keyroot)
        pprint(get_meta(opts['fileroot'], crypto_pass))
        return 0

    if mode == 'genkey':
        # FIXME, use openssl python module...
        os.system('openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=US/ST=CA/L=SF/O=A/CN=B" -keyout key.pem -out cert.pem')
        with open('crypto.pass', 'w') as f:
            f.write(hash_data(os.urandom(1024)))
        return 0

    hostport = args[0]
    args = args[1:]
    hostport = hostport.split(':')
    hostport = (hostport[0], int(hostport[1]))

    if mode == 'server':
        try:
            SaltyServer(hostport, **opts).serve_forever()
        except KeyboardInterrupt:
            log('Exit.')
    elif mode == 'client':
        SaltyClient(hostport, **opts).serve_forever()
    elif mode in ('cli', 'bootstrap'):
        if mode == 'bootstrap':
            server_opts = {k: v for k, v in opts.items() if k in ('fileroot', 'keyroot')}
            server = SaltyServer(hostport, **server_opts)
            server.start()
            client = SaltyClient(hostport, **opts)
            client_serve = gevent.spawn(client.serve_forever)

            # wait for client to connect
            while not server.clients:
                time.sleep(0.1)

            args = ['type=apply', 'bootstrap=true'] + args

        msg = {}
        # type=apply roles=foo,bar target=host1
        for arg in args:
            if not arg[0] == '-':
                k, v = arg.split('=', 1)

                # list of string
                if ',' in v or k in ('roles', 'skip'):
                    v = [_ for _ in v.split(',') if _]
                elif v.lower() == 'true':
                    v = True
                elif v.lower() == 'false':
                    v = False
                elif re.match('^[0-9]+$', v):
                    v = int(v)
                elif re.match('^[0-9]+\.[0-9]+$', v):
                    v = float(v)

                msg[k] = v

        total_errors = 0
        result = SaltyClient(hostport, **opts).run(msg)

        if result.get('error'):
            log_error(f'Errors in result:\n{result["error"]}')
            return 1

        if msg['type'] == 'apply':
            for host, roles in result['results'].items():
                changed = 0
                errors = 0
                host_elapsed = 0.0
                for role, cmds in roles.items():
                    host_elapsed += cmds['elapsed']
                    if sum(1 for _ in cmds['results'] if _['changed']):
                        changed += 1
                    if sum(1 for _ in cmds['results'] if _['rc'] > 0):
                        errors += 1

                total_errors += errors

                print()
                print(f'host:{host} elapsed:{host_elapsed:.3f} errors:{errors} changed:{changed}')
                for role, cmds in roles.items():
                    changed = sum(1 for _ in cmds['results'] if _['changed'])
                    errors = sum(1 for _ in cmds['results'] if _['rc'] > 0)
                    if changed or errors or verbose > 0:
                        print(f'  role:{role:11} elapsed:{cmds["elapsed"]:.3f} errors:{errors} changed:{changed}')
                        if cmds.get('output') and verbose > 1:
                            print(f'    Output:\n{cmds["output"]}')

                        if changed or errors or verbose > 1:
                            for result in cmds['results']:
                                if result['rc'] or result['changed'] or verbose > 1:
                                    output = result.pop('output', '').rstrip()
                                    s = f'    {result}'
                                    print_error(s) if result['rc'] else print(s)
                                    if output and (result['rc'] or verbose > 1):
                                        print_error(output) if result['rc'] else print(output)

            print()
            print(f'elapsed:{elapsed(start):.3f}')
        else:
            pprint(result)

        if mode == 'bootstrap':
            client_serve.kill()
            server.stop()

        if total_errors:
            return 1

    return 0

if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))

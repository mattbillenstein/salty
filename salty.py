#!/usr/bin/env python3

import gevent.monkey
gevent.monkey.patch_all()

import hashlib
import json
import os
import os.path
import socket
import ssl
import struct
import subprocess
import sys
import time
import traceback
import uuid
from collections import defaultdict
from queue import Queue
from pprint import pprint

import gevent
import gevent.server
import msgpack
import requests
from gevent.event import AsyncResult
from mako.template import Template

HERE = os.path.dirname(os.path.abspath(__file__))


def hash_data(data):
    return hashlib.sha1(data).hexdigest()

def hash_file(path):
    if os.path.isfile(path):
        with open(path, 'rb') as f:
            return hash_data(f.read())
    return None

def elapsed(start):
    return round(time.time() - start, 6)

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
        return sock.send(data)

    def recv_msg(self, sock):
        data = sock.read(4)
        if not data:
            return None
        size = struct.unpack('!I', data)[0]
        data = sock.read(size)
        while len(data) < size:
            data += sock.read(size - len(data))
        msg = msgpack.unpackb(data)
        return msg

    def _writer(self, sock, q):
        while 1:
            msg = q.get()
            sock.send(msg)

    def handle_future(self, msg, q):
        ar = self.futures.pop(msg['future_id'], None)
        if ar:
            ar.set(msg)

    def handle_msg(self, msg, q):
        method = getattr(self, 'handle_' + msg['type'], None)
        if method:
            gevent.spawn(method, msg, q)
        else:
            print(f'Unhandled message: {msg}')

    def handle(self, sock, addr):
        print(f'Connection established {addr[0]}:{addr[1]}')
        client_id = None
        q = Queue()
        g = gevent.spawn(self._writer, sock, q)
        try:
            while 1:
                try:
                    msg = self.recv_msg(sock)
                    if not msg:
                        print(f'Connection disconnected {addr[0]}:{addr[1]}')
                        break
                    if msg['type'] == 'identify':
                        client_id = msg['id']
                        self.clients[client_id] = q
                        self.facts[client_id] = msg['facts']
                    else:
                        self.handle_msg(msg, q)
                except ConnectionResetError:
                    print(f'Connection lost {addr[0]}:{addr[1]}')
                    break
        finally:
            if client_id:
                self.clients.pop(client_id)
            g.kill()

class SaltyServer(gevent.server.StreamServer, Reactor):
    def __init__(self, *args, **kwargs):
        self.clients = {}
        self.facts = {}
        self.futures = {}
        super().__init__(*args, **kwargs)

    def handle_ping(self, msg, q):
        self.send_msg(q, {'type': 'pong'})

    def handle_get_file(self, msg, q):
        path = os.path.join('files', msg['path'])
        with open(path, 'rb') as f:
            data = f.read()

        msg['type'] = 'future'

        hash = hash_data(data)
        if msg.get('hash') != hash:
            msg['data'] = data
            msg['hash'] = hash

        msg['mode'] = os.stat(path).st_mode & 0o777
        self.send_msg(q, msg)

    def handle_apply(self, msg, q):
        results = defaultdict(dict)

        # apply roles to target servers
        meta = {}
        with open('meta/servers.py') as f:
            exec(f.read(), meta)
            meta.pop('__builtins__')

        target = msg.get('target')
        roles = msg.get('roles')

        for id, q2 in self.clients.items():
            if id not in meta:
                print('Apply missing host {id} in metadata')
                continue

            for role in meta[id]['roles']:
                if roles and role not in roles:
                    results[id][role] = {'results': [{'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0}], 'elapsed': 0.0}
                    continue

                # FIXME, regex and meta matching?
                if target and not id.startswith(target):
                    results[id][role] = {'results': [{'rc': 0, 'cmd': '...host skipped...', 'elapsed': 0.0}], 'elapsed': 0.0}
                    continue

                with open(f'roles/{role}.py') as f:
                    content = f.read()
                msg = {'type': 'run', 'content': content, 'context': {'id': id, 'role': role, 'meta': meta, 'facts': self.facts}}
                results[id][role] = gevent.spawn(self.do_rpc, q2, msg)

        for id, d in results.items():
            for role, g in d.items():
                if not isinstance(g, dict):
                    d[role] = g.get()['result']

        self.send_msg(q, {'type': 'apply_result', 'results': results})

class SaltyClient(Reactor):
    def __init__(self, addr, keyfile='key.pem', certfile='cert.pem', id=None, path=None):
        self.addr = addr
        self.id = id
        self.keyfile = keyfile
        self.certfile = certfile
        self.path = path
        self.futures = {}

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = ssl.wrap_socket(sock, keyfile=self.keyfile, certfile=self.certfile)
        sock.connect(self.addr)
        return sock

    def get_facts(self):
        facts = {}

        r = requests.get('https://vazor.com/ip')
        assert r.ok, r.text
        facts['public_ip'] = r.text.strip()

        cmd = ['hostname', '-I']
        if sys.platform == 'darwin':
            cmd = ['ipconfig', 'getifaddr', 'en0']
        p = subprocess.run(cmd, capture_output=True)
        assert p.returncode == 0, p
        facts['ip'] = p.stdout.decode('utf8').strip().split()[0]

        return facts

    def handle_pong(self, msg, q):
        pass

    def handle_run(self, msg, q):
        print(f'Run {msg}')
        start = time.time()
        results = []

        context = msg['context']
        context['id'] = self.id

        def copy(src, dst):
            start = time.time()
            result = {'cmd': f'copy({src}, {dst})', 'rc': 0, 'changed': False}
            results.append(result)
            try:
                dst = self.path + dst
                hash = hash_file(dst)
                res = self.get_file(q, src, hash=hash)

                if res['hash'] != hash:
                    result['changed'] = True
                    os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                    with open(dst, 'wb') as f:
                        f.write(res['data'])

                if os.stat(dst).st_mode & 0o777 != res['mode']:
                    os.chmod(dst, res['mode'])
                    result['changed'] = True
            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()
                result['changed'] = True

            result['elapsed'] = elapsed(start)
            return result

        def render(src, dst, **kw):
            start = time.time()
            result = {'cmd': f'render({src}, {dst})', 'rc': 0, 'changed': False}
            results.append(result)

            try:
                dst = self.path + dst
                hash = hash_file(dst)
                res = self.get_file(q, src, hash=hash)

                template = res['data'].decode('utf8')
                data = Template(template).render(**context, **kw).encode('utf8')
                hash_new = hash_data(data)

                if hash_new != hash:
                    result['changed'] = True
                    os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                    with open(dst, 'wb') as f:
                        f.write(data)

                if os.stat(dst).st_mode & 0o777 != res['mode']:
                    os.chmod(dst, res['mode'])
                    result['changed'] = True
            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()
                result['changed'] = True

            result['elapsed'] = elapsed(start)
            return result

        def shell(cmds):
            start = time.time()
            result = {'cmd': f'shell({cmds})', 'rc': 0, 'changed': True}
            results.append(result)
            p = subprocess.run(cmds, shell=True, capture_output=True)
            result['rc'] = p.returncode
            result['output'] = p.stdout.decode('utf8') + '\n' + p.stderr.decode('utf8')
            result['elapsed'] = elapsed(start)
            return result

        output = []
        def capture_print(x):
            output.append(str(x))

        g = {'copy': copy, 'render': render, 'shell': shell, 'print': capture_print}
        content = msg.pop('content')
        try:
            exec(content, g)
        except Exception as e:
            result = {'cmd': f'error in exec', 'rc': 1, 'changed': True}
            result['error'] = traceback.format_exc()
            results.append(result)

        msg['type'] = 'future'
        msg['result'] = {'results': results, 'output': '\n'.join(output), 'elapsed': elapsed(start)}
        self.send_msg(q, msg)

    def get_file(self, sock, path, **opts):
        msg = {'type': 'get_file', 'path': path}
        msg.update(opts)
        return self.do_rpc(sock, msg)

    def serve_forever(self):
        while 1:
            try:
                g = None
                sock = self.connect()
                g = gevent.spawn(self.handle, sock, self.addr)

                self.send_msg(sock, {'type': 'identify', 'id': self.id, 'facts': self.get_facts()})
                while 1:
                    self.send_msg(sock, {'type': 'ping'})
                    time.sleep(5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f'Exception in client serve: {traceback.format_exc()}')
                time.sleep(3)
            finally:
                if g:
                    g.kill()

    def run(self, msg):
        sock = self.connect()
        self.send_msg(sock, msg)
        return self.recv_msg(sock)

def main(mode, hostport, *args):
    hostport = hostport.split(':')
    hostport = (hostport[0], int(hostport[1]))

    verbose = 0
    opts = dict(keyfile='key.pem', certfile='cert.pem')
    for arg in args:
        if arg.startswith('-v'):
            verbose = arg.count('v')
        elif arg.startswith('--'):
            k, v = arg[2:].split('=', 1)
            opts[k] = v

    if mode == 'server':
        SaltyServer(hostport, **opts).serve_forever()
    elif mode == 'client':
        # --id=host1 --path=tmp/host1
        SaltyClient(hostport, **opts).serve_forever()
    elif mode == 'cli':
        msg = {}
        # type=apply roles=foo,bar target=host1
        for arg in args:
            if not arg[0] == '-':
                k, v = arg.split('=', 1)
                msg[k] = v.split(',') if ',' in v else v

        result = SaltyClient(hostport, **opts).run(msg)
        for host, roles in result['results'].items():
            for role, cmds in roles.items():
                print(f'host:{host} role:{role} elapsed:{cmds["elapsed"]}')
                if cmds.get('output') and verbose > 0:
                    print(f'  Output:\n{cmds["output"]}')
                for result in cmds['results']:
                    if result['rc'] or result.get('error') or verbose > 0:
                        output = result.pop('output', None)
                        print(f'  {result}')
                        if output and verbose > 1:
                            print(output.rstrip())

    return 0

if __name__ == '__main__':
    main(*sys.argv[1:])

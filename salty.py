#!/usr/bin/env python3

import gevent.monkey
gevent.monkey.patch_all()

import fnmatch
import hashlib
import json
import os
import os.path
import platform
import re
import shutil
import socket
import ssl
import stat
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
import mako.exceptions
import mako.template
import msgpack
import requests
from gevent.event import AsyncResult

import crypto
from compat import grp, pwd, useradd_command, get_ip_addresses

DEFAULT_USER = pwd.getpwuid(os.getuid()).pw_name

# convenience imports used in roles and mako
IMPORTS = [
    'import os',
    'import os.path',
    'import json',
]

_print = print
def print(*args):
    _print(*args)
    sys.stdout.flush()

def print_error(*args):
    if sys.stdout.isatty():
        args = [f'\033[1;31m{_}\033[0m' for _ in args]
    print(*args)

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
        with gevent.Timeout(30):
            sock.send(data)

    def recv_msg(self, sock, timeout=30):
        with gevent.Timeout(timeout):
            data = sock.read(4)
        if not data:
            raise ConnectionError('Socket dead')

        size = struct.unpack('!I', data)[0]
        if size > 100_000_000:
            raise ConnectionError('Message too big')

        data = b''
        for i in range(50):
            with gevent.Timeout(timeout):
                data += sock.read(size - len(data))
            if len(data) == size:
                return msgpack.unpackb(data)
            time.sleep(0.1)

        raise ConnectionError('Could not read {size} bytes')

    def _writer(self, sock, q):
        while 1:
            msg = q.get()
            with gevent.Timeout(30):
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
            fh = sock.makefile(mode='b')
            while 1:
                try:
                    msg = self.recv_msg(fh)
                    if msg['type'] == 'identify':
                        client_id = msg['id']
                        print(f'id:{client_id} facts:{msg["facts"]}')
                        self.clients[client_id] = q
                        self.facts[client_id] = msg['facts']
                    else:
                        self.handle_msg(msg, q)
                except OSError:
                    print(f'Connection lost {addr[0]}:{addr[1]}')
                    break
                except gevent.Timeout:
                    print(f'Connection lost {addr[0]}:{addr[1]} timeout')
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
        self.fileroot = kwargs.pop('fileroot', os.getcwd())

        keyroot = kwargs.pop('keyroot', os.getcwd())
        kwargs['keyfile'] = os.path.join(keyroot, 'key.pem')
        kwargs['certfile'] = os.path.join(keyroot, 'cert.pem')

        self.crypto_pass = None
        fname = os.path.join(keyroot, 'crypto.pass')
        if os.path.exists(fname):
            with open(fname) as f:
                self.crypto_pass = f.read().strip()

        super().__init__(*args, **kwargs)

    def handle_ping(self, msg, q):
        self.send_msg(q, {'type': 'pong'})

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
            msg['error'] = traceback.format_exc()

        self.send_msg(q, msg)

    def handle_apply(self, msg, q):
        start = time.time()
        results = defaultdict(dict)
        msg_result = {'type': 'apply_result', 'results': results}

        try:
            # apply roles to target servers
            meta = {}
            for fname in ('hosts', 'envs', 'clusters'):
                with open(os.path.join(self.fileroot, 'meta', f'{fname}.py')) as f:
                    meta[fname] = {}
                    exec(f.read(), meta[fname])
                    for k in list(meta[fname]):
                        if k.startswith('_'):
                            meta[fname].pop(k)

            # unwind cluster -> id in hosts and apply facts/envs/clusters
            hosts = {}
            for cluster, servers in meta['hosts'].items():
                for id, v in servers.items():
                    # skip disconnected / non-existing hosts
                    if id not in self.facts:
                        continue

                    v['cluster'] = cluster
                    v['facts'] = self.facts[id]
                    v['vars'] = {}
                    v['vars'].update(meta['envs'][v['env']])
                    v['vars'].update(meta['clusters'][cluster])
                    hosts[id] = v

            target = msg.get('target')
            target_cluster = None
            if target and target.startswith('cluster:'):
                target_cluster = target.split(':')[1]
                target = None

            crypto.decrypt_dict(meta, self.crypto_pass)

            # roles to apply, if empty, apply all host roles
            roles = msg.get('roles', [])
            # roles to skip unless given explictely
            skip = [_ for _ in msg.get('skip', []) if _ not in roles]

            context = {k: v for k, v in msg.items() if k not in ('type', 'target', 'roles', 'skip')}

            for id, q2 in self.clients.items():
                if id not in hosts:
                    print(f'Apply missing host {id} in metadata')
                    continue

                if target_cluster and hosts[id]['cluster'] != target_cluster:
                    continue

                for role in hosts[id]['roles']:
                    if not os.path.isfile(os.path.join(self.fileroot, 'roles', f'{role}.py')):
                        # roles are sometimes just tags, just silently ignore
                        # missing role .py files
                        # results[id][role] = {'results': [{'rc': 1, 'cmd': '...role missing...', 'elapsed': 0.0}], 'elapsed': 0.0}
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
                        host_roles[role] = self.do_rpc(*tup)['result']

            greenlets = []
            for id, host_roles in results.items():
                g = gevent.spawn(dispatch, host_roles)
                greenlets.append(g)

            gevent.wait(greenlets)

        except:
            msg_result['error'] = traceback.format_exc()

        msg_result['elapsed'] = elapsed(start)
        self.send_msg(q, msg_result)

class SaltyClient(Reactor):
    def __init__(self, addr, keyroot=os.getcwd(), id=None, path=''):
        self.addr = addr
        self.id = id
        self.keyroot = keyroot
        self.path = path
        self.futures = {}

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = ssl.wrap_socket(
            sock,
            keyfile=os.path.join(self.keyroot, 'key.pem'),
            certfile=os.path.join(self.keyroot, 'cert.pem'),
        )
        sock.connect(self.addr)
        return sock

    def get_facts(self):
        facts = {}

        facts.update(get_ip_addresses())

        uname = platform.uname()
        facts['kernel'] = uname.system
        facts['machine'] = uname.machine

        return facts

    def handle_pong(self, msg, q):
        pass

    def handle_run(self, msg, q):
        print(f'Run {msg}')
        start = time.time()
        results = []

        def get_ips(role, key='private_ip'):
            # return ip addresses of hosts serving the role in the same
            # cluster...
            ips = []
            cluster = context['me']['cluster']
            if cluster == 'local':
                if role in context['me']['roles']:
                    ips.append('127.0.0.1')
                return ips
            for id, h in context['hosts'].items():
                if h['cluster'] == cluster and role in h['roles']:
                    ips.append(h['facts'][key])
            ips.sort()
            return ips

        context = dict(msg['context'])
        context['get_ips'] = get_ips

        def _set_user_and_mode(path, user=DEFAULT_USER, mode=None):
            changed = False
            
            st = os.stat(path)

            if mode is None:
                mode = 0o644
                if stat.S_ISDIR(st.st_mode):
                    mode = 0o755

            if st.st_mode & 0o777 != mode:
                os.chmod(path, mode)
                changed = True

            u = pwd.getpwnam(user)
            if st.st_uid != u.pw_uid or st.st_gid != u.pw_gid:
                os.chown(path, u.pw_uid, u.pw_gid)
                changed = True

            return changed

        def makedirs(path, user=DEFAULT_USER, mode=0o755):
            start = time.time()
            result = {'cmd': f'makedirs({path}, {user}, 0o{mode:o})', 'rc': 0, 'changed': False, 'created': False}
            results.append(result)
            try:
                path = self.path + path

                if not os.path.isdir(path):
                    os.makedirs(path, mode=mode)
                    result['created'] = True
                    result['changed'] = True

                if _set_user_and_mode(path, user, mode):
                    result['changed'] = True
            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()

            result['elapsed'] = elapsed(start)
            return result

        def remove(path):
            start = time.time()
            result = {'cmd': f'remove({path})', 'rc': 0, 'changed': False, 'created': False, 'removed': False}
            results.append(result)
            try:
                path = self.path + path

                if os.path.exists(path):
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                    result['removed'] = True
                    result['changed'] = True

            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()

            result['elapsed'] = elapsed(start)
            return result

        def copy(src, dst, user=DEFAULT_USER, mode=0o644):
            start = time.time()
            result = {'cmd': f'copy({src}, {dst})', 'rc': 0, 'changed': False}
            results.append(result)
            try:
                dst = self.path + dst
                hash = hash_file(dst)
                result['created'] = hash is None

                res = self.get_file(q, src, hash=hash)
                assert not res.get('error'), res['error']

                if res['hash'] != hash:
                    result['changed'] = True
                    os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                    with open(dst, 'wb') as f:
                        f.write(res['data'])

                if _set_user_and_mode(dst, user, mode):
                    result['changed'] = True
            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()

            result['elapsed'] = elapsed(start)
            return result

        def render(src, dst, user=DEFAULT_USER, mode=0o644, **kw):
            start = time.time()
            result = {'cmd': f'render({src}, {dst})', 'rc': 0, 'changed': False}
            results.append(result)

            try:
                dst = self.path + dst
                hash = hash_file(dst)
                result['created'] = hash is None

                res = self.get_file(q, src, hash=hash)
                assert not res.get('error'), res['error']

                template = res['data'].decode('utf8')
                try:
                    data = mako.template.Template(template, imports=IMPORTS).render(**context, **kw).encode('utf8')
                except Exception as e:
                    # mako text_error_template gives us a dump of where the
                    # error in the template occurred...
                    result['rc'] = 1
                    result['error'] = mako.exceptions.text_error_template().render()
                    result['elapsed'] = elapsed(start)
                    return result

                hash_new = hash_data(data)

                if hash_new != hash:
                    result['changed'] = True
                    os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                    with open(dst, 'wb') as f:
                        f.write(data)

                if _set_user_and_mode(dst, user, mode):
                    result['changed'] = True
            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()

            result['elapsed'] = elapsed(start)
            return result

        def line_in_file(line, path, user=DEFAULT_USER, mode=0o644):
            start = time.time()
            result = {'cmd': f'line_in_file({path}, {line})', 'rc': 0, 'changed': False, 'created': False}
            results.append(result)

            try:
                path = self.path + path
                if os.path.isfile(path):
                    with open(path, 'rb') as f:
                        content = f.read()
                else:
                    result['created'] = True
                    content = b''
                    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)

                line = line.encode('utf8')

                if line not in content:
                    with open(path, 'wb') as f:
                        if content and not content.endswith(b'\n'):
                            content += 'b\n'
                        f.write(content + line + b'\n')

                if _set_user_and_mode(path, user, mode):
                    result['changed'] = True
            except Exception as e:
                result['rc'] = 1
                result['error'] = traceback.format_exc()

            result['elapsed'] = elapsed(start)
            return result

        def symlink(src, dst):
            start = time.time()
            result = {'cmd': f'symlink({src}, {dst})', 'rc': 0, 'changed': False, 'created': False}
            results.append(result)

            try:
                st = os.lstat(dst)
                if stat.S_ISDIR(st.st_mode):
                    shutil.rmtree(dst)
                elif stat.S_ISREG(st.st_mode):
                    os.remove(dst)
                elif stat.S_ISLNK(st.st_mode):
                    target = os.readlink(dst)
                    if target != src:
                        os.remove(dst)
            except FileNotFoundError:
                pass

            if not os.path.exists(dst):
                os.symlink(src, dst)
                result['created'] = True
                result['changed'] = True

            return result

        def shell(cmds, **kw):
            start = time.time()
            result = {'cmd': f'shell({cmds})', 'rc': 0, 'changed': True}
            results.append(result)
            p = subprocess.run(cmds, shell=True, capture_output=True, **kw)
            result['rc'] = p.returncode
            result['output'] = p.stdout.decode('utf8') + '\n' + p.stderr.decode('utf8')
            result['elapsed'] = elapsed(start)
            return result

        def useradd(username, system=False):
            # add user and matching group if they do not exist
            start = time.time()
            result = {'cmd': f'useradd({username}, system={system})', 'rc': 0, 'changed': False, 'created': False}
            results.append(result)
            try:
                pwd.getpwnam(username)
            except KeyError:
                rc = shell(useradd_command(username, system))
                result['created'] = True
                result['changed'] = True
                result['output'] = rc['output']
            result['elapsed'] = elapsed(start)
            return result

        def is_changed():
            # return True if anything changed up to this point in the current
            # run - useful for restart commands....
            return any([_['changed'] for _ in results])

        output = []
        def capture_print(x):
            output.append(str(x))

        g = {
            'copy': copy,
            'is_changed': is_changed,
            'line_in_file': line_in_file,
            'makedirs': makedirs,
            'print': capture_print,
            'render': render,
            'remove': remove,
            'shell': shell,
            'symlink': symlink,
            'useradd': useradd,
        }
        g.update(context)
        content = '\n'.join(IMPORTS) + '\n' + msg.pop('content')
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
            except Exception:
                print(f'Exception in client serve: {traceback.format_exc()}')
                time.sleep(3)
            except gevent.Timeout:
                print(f'Exception in client serve: {traceback.format_exc()} timeout')
                time.sleep(3)
            finally:
                if g:
                    g.kill()

    def run(self, msg):
        sock = self.connect()
        self.send_msg(sock, msg)
        return self.recv_msg(sock, timeout=600)

def main(mode, hostport, *args):
    start = time.time()

    hostport = hostport.split(':')
    hostport = (hostport[0], int(hostport[1]))

    verbose = 0
    opts = {}

    # consume salty args, they begin with a -
    # fixme - argparse
    for arg in args:
        if arg.startswith('-v'):
            verbose = arg.count('v')
        elif arg.startswith('--'):
            k, v = arg[2:].split('=', 1)
            opts[k] = v

    # filter run args
    args = [_ for _ in args if not _.startswith('-')]

    if mode == 'server':
        try:
            SaltyServer(hostport, **opts).serve_forever()
        except KeyboardInterrupt:
            print('Exit.')
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
            print(f'Exception in apply:\n{result["error"]}')

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

        if mode == 'bootstrap':
            client_serve.kill()
            server.stop()

        print()
        print(f'elapsed:{elapsed(start):.3f}')

        if total_errors:
            return 1

    return 0

if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))

import fnmatch
import os
import os.path
import subprocess
import time
import traceback
from collections import defaultdict

import gevent
import gevent.server

from lib import crypto, operators
from lib.net import Reactor
from lib.util import elapsed, get_crypto_pass, hash_data, log, log_error

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

    def handle_server_shell(self, msg, q):
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

    def get_hosts(self, meta):
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

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

from lib.net import MsgMixin
from lib.util import elapsed, get_crypto_pass, get_meta, log, log_error


class SaltyServer(gevent.server.StreamServer, MsgMixin):
    def __init__(self, *args, **kwargs):
        self.clients = {}
        self.facts = {}
        self.futures = {}

        self.fileroot = kwargs.pop('fileroot', os.getcwd())
        self.keyroot = kwargs.pop('keyroot', os.getcwd())
        self.crypto_pass = get_crypto_pass(self.keyroot)

        super().__init__(*args, **kwargs)

    def handle(self, sock, addr):
        log(f'Connection established {addr[0]}:{addr[1]}')

        # With gevent we were getting bottle-necked in the server process with
        # many clients and/or large file transfers since all the file I/O, TLS,
        # and networking/messaging had to be done on a single cpu thread.
        #
        # So, having a thread or process per client for this is ideal, but
        # given the GIL threads are probably out, and given gevent, fork() et
        # al are problematic.
        #
        # So, I tried gipc, geventmp, and patched multiprocessing - but each
        # one is broken in various ways, and I can't find good evidence the
        # first two are heavily used.
        #
        # All we want is to get a new process with a valid handle to the client
        # socket, a reliable way to communicate with it, and with a new event
        # loop...
        #
        # The simplest thing I've come across seems to be to create a socket
        # pair and pass one end of that and the client socket via:
        #
        #    subprocess.run([sys.argv[0], ...], pass_fds=(sock, sock2))
        #
        # Under the hood, this does fork / exec closing everything we're not
        # interested in in-between; and the exec replaces the process, so we
        # discard the event loop as well.
        #
        # This probably isn't that fast compared to threads or just fork(), but
        # for long-lived connections (hours, days, weeks) should be more than
        # fine.
        #
        # The client process also needs the keyroot since we need to wrap the
        # passed client socket with tls; and fileroot to directly do
        # file-serving. This offloads these cpu-bound tasks to a process per
        # client which means we shouldn't get bottlenecked on the single server
        # process as before.

        client_sock, server_sock = socket.socketpair()

        if 'salty.py' in sys.argv[0]:
            # use the same executable so we land in the same venv
            exe = [sys.executable, sys.argv[0]]
        else:
            exe = [sys.argv[0]]

        args = [
            'client-proc',
            f'--keyroot={self.keyroot}', f'--fileroot={self.fileroot}',
            f'--client-fd={sock.fileno()}', f'--server-fd={server_sock.fileno()}',
        ]
        log(f'Running: {exe + args}')
        p = subprocess.Popen(exe + args, pass_fds=(sock.fileno(), server_sock.fileno()))

        # Close fds handled by the client proc
        sock.close()
        server_sock.close()

        client_id = None
        client_q = Queue()
        g = gevent.spawn(self._writer, client_q, client_sock)

        try:
            while 1:
                try:
                    # client proc or writer dead, break and exit
                    if g.dead or p.poll() is not None:
                        break

                    msg = self.recv_msg(client_sock)
                    log('Server got', msg)
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

            if p.poll() is None:
                p.kill()
            if not g.dead:
                g.kill()

            client_sock.close()

    def handle_ping(self, msg, q):
        if facts := msg.get('facts'):
            self.facts[msg['id']] = facts
        q.put({'type': 'pong'})

    def handle_hosts(self, msg, q):
        meta = get_meta(self.fileroot, self.crypto_pass)
        hosts = self.get_hosts(meta)
        msg['hosts'] = {k: v for k, v in hosts.items() if v['facts']}
        q.put(msg)

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
                    results[id][role] = (msg, q2)

            # scatter by host, then collect - roles must be run sequentially
            def dispatch(host_roles):
                for role, tup in list(host_roles.items()):
                    # if dict, either host or role was skipped and a stub
                    # result returned... Otherwise, do rpc.
                    if not isinstance(tup, dict):
                        msg, q = tup
                        ctx = msg['context']
                        t = time.time()
                        host_roles[role] = m = self.do_rpc(msg, q)['result']
                        rc = sum(_['rc'] for _ in m['results'])
                        log('RPC', ctx['id'], ctx['role'], rc, f'{elapsed(t):.6f}')

            greenlets = []
            for id, host_roles in results.items():
                g = gevent.spawn(dispatch, host_roles)
                greenlets.append(g)

            gevent.wait(greenlets)

        except Exception:
            log_error('Exception handling msg in handle_apply:', msg)
            tb = traceback.format_exc().strip()
            log(tb)
            msg_result['error'] = tb

        msg_result['elapsed'] = elapsed(start)
        q.put(msg_result)

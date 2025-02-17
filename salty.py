#!/usr/bin/env python3

import gevent.monkey
gevent.monkey.patch_all()

import multiprocessing
import os
import re
import sys
import time

import gevent

from lib.util import elapsed, get_crypto_pass, get_facts, get_meta, hash_data, log, log_error, pprint, print_error
from client import SaltyClient
from server import SaltyServer


def parse_args(args):
    # FIXME, argparse?
    mode = 'help'
    if args:
        mode, args = args[0], args[1:]

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

    hostport = None
    if args:
        hostport = args[0]
        args = args[1:]
        hostport = hostport.split(':')
        hostport = (hostport[0], int(hostport[1]))

    return mode, hostport, args, opts, verbose

def cli(hostport, args, opts, verbose, bootstrap=False):
    # Salty CLI entry point
    #
    # Instantiate a Client and run a command specified from cli args
    #
    # Optionally in bootstrap mode, also instantiate the Client/Server running
    # in their own greenlets that the CLI Client will use.
    start = time.time()

    if bootstrap:
        server_opts = {k: v for k, v in opts.items() if k in ('fileroot', 'keyroot')}
        server = SaltyServer(hostport, **server_opts)
        server.start()
        client = SaltyClient(hostport, **opts)
        client_serve = gevent.spawn(client.serve_forever)

        # wait for client to connect
        while not server.clients:
            time.sleep(0.1)

        args = ['type=apply', 'bootstrap=true'] + args

    # Capture message args from cli, ex:
    #
    # type=apply roles=foo,bar target=host1 i=1 f=3.14 b=true
    #
    # {'type': 'apply', 'roles': ['foo', 'bar'], 'target': 'host1' 'i': 1, 'f': 3.14, 'b': True}
    msg = {}
    for arg in args:
        if not arg[0] == '-':
            k, v = arg.split('=', 1)

            if ',' in v or k in ('roles', 'skip'):
                # list of string
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

    # Unpack apply result and based on verbosity, display changed/errored
    # hosts/roles, all hosts/roles, or all hosts/roles/cmds
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
        # otherwise, just pprint the message
        pprint(result)

    if bootstrap:
        client_serve.kill()
        server.stop()

    if total_errors:
        return 1

    return 0

def main(*args):
    mode, hostport, args, opts, verbose = parse_args(args)

    modes = ('facts', 'meta', 'genkey', 'server', 'client', 'cli', 'bootstrap')
    if mode == 'help' or mode not in modes:
        print(f"Usage: ./salty.py ({' | '.join(modes)}) [args]")

    elif mode == 'facts':
        # Show facts for current host
        pprint(get_facts())

    elif mode == 'meta':
        # Read and display metadata directly
        fileroot = opts.get('fileroot', os.getcwd())
        crypto_pass = None
        if keyroot := opts.get('keyroot'):
            crypto_pass = get_crypto_pass(keyroot)
        pprint(get_meta(fileroot, crypto_pass))

    elif mode == 'genkey':
        # Generate local tls keys and random crypto pass - this can be used to
        # init a new installation's keys
        #
        # FIXME, use openssl python module?
        os.system('openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=US/ST=CA/L=SF/O=A/CN=B" -keyout key.pem -out cert.pem')
        with open('crypto.pass', 'w') as f:
            f.write(hash_data(os.urandom(1024)))

    elif mode == 'server':
        try:
            SaltyServer(hostport, **opts).serve_forever()
        except KeyboardInterrupt:
            log('Exit.')

    elif mode == 'client':
        try:
            SaltyClient(hostport, **opts).serve_forever()
        except KeyboardInterrupt:
            log('Exit.')

    elif mode in ('cli', 'bootstrap'):
        return cli(hostport, args, opts, verbose, mode == 'bootstrap')

    return 0

if __name__ == '__main__':
    multiprocessing.set_start_method('forkserver')
    sys.exit(main(*sys.argv[1:]))

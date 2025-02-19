import hashlib
import json
import sys
import time
import os.path

from .compat import get_facts # noqa
from . import crypto

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

def hash_data(data):
    return hashlib.sha1(data).hexdigest()

def hash_file(path):
    if os.path.isfile(path):
        with open(path, 'rb') as f:
            h = hashlib.sha1()
            while 1:
                data = f.read(8 * 1024 * 1024)
                if not data:
                    break
                h.update(data)
            return h.hexdigest()
    return None

def elapsed(start):
    return round(time.time() - start, 6)

def get_crypto_pass(keyroot):
    fname = os.path.join(keyroot, 'crypto.pass')
    if os.path.exists(fname):
        with open(fname) as f:
            return f.read().strip()
    return None

def get_meta(fileroot, crypto_pass=None):
    # read installation metadata and optionally decrypt secrets
    meta = {}
    metapy = os.path.join(fileroot, 'meta.py')
    if os.path.isfile(metapy):
        # new format, single meta.py file
        with open(metapy) as f:
            exec(f.read(), meta)
        meta = {k: v for k, v in meta.items() if k[0] != '_'}
    else:
        # old format, can probably remove now as of 2/15/2025, but leave this
        # around awhile.
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

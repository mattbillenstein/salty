import hashlib
import json
import multiprocessing
import sys
import threading
import time
import os.path

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

def spawn_process(func, args=None, kwargs=None):
    args = args or []
    kwargs = kwargs or {}
    p = multiprocessing.Process(target=func, args=args, kwargs=kwargs, daemon=True)
    p.start()
    while not p.pid:
        time.sleep(0.01)
    return p

def spawn_thread(func, args=None, kwargs=None):
    args = args or []
    kwargs = kwargs or {}
    t = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True)
    t.start()
    return t

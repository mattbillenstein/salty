#!/usr/bin/env python3

import ipaddress
import json
import os
import os.path
import re
import subprocess
import sys

if sys.platform == 'darwin':
    import time
    import uuid

    import pwd as _pwd
    import grp as _grp

    class _base:
        @classmethod
        def get_recs(cls):
            if not cls._cache or (time.time() - cls._cache_ts) > 100.0:
                p = subprocess.run(f'dscacheutil -q {cls.query}', shell=True, capture_output=True)
                assert p.returncode == 0, p
                output = p.stdout.decode('utf8').split('\n')

                recs = []
                for line in output:
                    line = line.strip()
                    if not line:
                        continue

                    k, v = line.split(':', 1)
                    v = v.strip()

                    if k not in cls.fields:
                        continue

                    if k == 'name':
                        r = {}
                        recs.append(r)

                    if k in ('uid', 'gid'):
                        v = int(v)

                    if k == 'users':
                        v = v.split()

                    r[k] = v

                cls._cache = [cls.struct(tuple(_.get(k) for k in cls.fields)) for _ in recs]
                cls._cache_ts = time.time()

            return cls._cache

    class pwd(_base):
        query = 'user'
        fields = ('name', 'password', 'uid', 'gid', 'gecos', 'dir', 'shell')
        struct = _pwd.struct_passwd
        _cache = None
        _cache_ts = 0.0

        @classmethod
        def getpwnam(cls, name):
            for r in cls.get_recs():
                if r.pw_name == name:
                    return r
            raise KeyError(f'Missing name {name}')

        @classmethod
        def getpwuid(cls, uid):
            for r in cls.get_recs():
                if r.pw_uid == uid:
                    return r
            raise KeyError(f'Missing uid {uid}')

    class grp(_base):
        query = 'group'
        fields = ('name', 'password', 'gid', 'users')
        struct = _grp.struct_group
        _cache = None
        _cache_ts = 0.0

        @classmethod
        def getgrnam(cls, name):
            for r in cls.get_recs():
                if r.gr_name == name:
                    return r
            raise KeyError(f'Missing name {name}')

        @classmethod
        def getgrgid(cls, gid):
            for r in cls.get_recs():
                if r.gr_gid == gid:
                    return r
            raise KeyError(f'Missing gid {gid}')

    def useradd_command(username, system=False):
        # find the highest uid+1, and gid+1
        uid = max(_.pw_uid for _ in pwd.get_recs()) + 1
        gid = max(_.gr_gid for _ in grp.get_recs()) + 1

        password = str(uuid.uuid4())
        base = f'dscl . -create /Users/{username}'
        baseg = f'dscl . -create /Groups/{username}'
        cmds = [
            baseg,
            f'{baseg} gid {gid}',
            f'{baseg} RealName "{username}"',
            f'{baseg} passwd "*"',
            base,
            f'{base} UniqueID {uid}',
            f'{base} PrimaryGroupID {gid}',
            f'{base} UserShell /bin/bash',
            f'{base} RealName "{username}"',
            f'{base} NFSHomeDirectory /Users/{username}',
            f'dscl . -passwd /Users/{username} {password}',
            f'mkdir -p /Users/{username}',
            f'chown {username}:staff /Users/{username}',
        ]
        if system:
            cmds.append(f'{base} IsHidden 1')

        pwd._cache = None
        grp._cache = None
        return '; '.join(cmds)

    def get_networking():
        device = re.compile('^([a-zA-Z0-9]+): ')
        mac = re.compile('^\s+ether ([0-9a-f:]{17})')
        inet = re.compile('^\s+inet[6]{0,1} ([a-f0-9\.:]+)(?:%[a-zA-Z0-9]+)? (netmask|prefixlen) ([a-f0-9x]+)')

        p = subprocess.run("ifconfig", shell=True, capture_output=True)
        assert p.returncode == 0, p
        lines = p.stdout.decode('utf8').strip().split('\n')

        L = []
        for line in lines:
            if mobj := device.match(line):
                d = {'device': mobj.group(1)}
                L.append(d)
            elif mobj := mac.match(line):
                d['mac'] = mobj.group(1)
            elif mobj := inet.match(line):
                ip, key, netmask = mobj.groups()
                if netmask.startswith('0x'):
                    netmask = str(bin(int(netmask, 16)).count('1'))
                ip += '/' + netmask

                addr = ipaddress.ip_interface(ip)
                if f'ipv{addr.version}' not in d:  # take first
                    d[f'ipv{addr.version}'] = str(addr.ip)
                    d[f'ipv{addr.version}_network'] = str(addr.network)
                    d['is_loopback'] = addr.is_loopback
                    d['is_private'] = addr.is_private and not addr.is_loopback
                    d['is_public'] = addr.is_global

        # filter out stuff without ipv4 addresses
        L = [_ for _ in L if 'ipv4' in _]
        return {'interfaces': L}

    def get_cpu_count():
        return os.cpu_count()

    def get_mem_gb():
        return round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 2**30, 1)

elif sys.platform == 'linux':
    import pwd
    import grp

    if os.path.exists('/etc/alpine-release'):
        def useradd_command(username, system=False):
            system = ' -S' if system else ''
            return f'addgroup {username} || true; pw="$(head -c 20 /dev/urandom | base64 | head -c 10)"; ( echo "$pw"; echo "$pw" ) | adduser {system} -G {username} -s /bin/bash {username}'
    else:
        def useradd_command(username, system=False):
            system = ' --system' if system else ''
            return f'useradd --create-home --user-group{system} --shell /bin/bash {username}'

    def get_networking():
        device = re.compile('^[0-9]+: ([a-zA-Z0-9@]+): <')
        link = re.compile('^\s+link/[^ ]+ ([0-9a-f:]{17}) ')
        inet = re.compile('^\s+inet[6]{0,1} ([a-f0-9\.:]+/[0-9]+) ')

        p = subprocess.run("ip addr", shell=True, capture_output=True)
        assert p.returncode == 0, p

        lines = p.stdout.decode('utf8').strip().split('\n')

        L = []
        for line in lines:
            if mobj := device.match(line):
                d = {'device': mobj.group(1)}
                for k in ('is_bridge', 'is_loopback', 'is_private', 'is_public'):
                    d[k] = False
                L.append(d)
            elif mobj := link.match(line):
                d['mac'] = mobj.group(1)
            elif mobj := inet.match(line):
                addr = ipaddress.ip_interface(mobj.group(1))
                d[f'ipv{addr.version}'] = str(addr.ip)
                d[f'ipv{addr.version}_network'] = str(addr.network)
                if addr.version == 4:
                    # FIXME, multiple ipv4 addresses on a single interface?
                    d['is_bridge'] = os.path.exists(f'/sys/class/net/{d["device"]}/bridge')
                    d['is_loopback'] = addr.is_loopback
                    d['is_private'] = addr.is_private and not addr.is_loopback and not d['is_bridge']
                    d['is_public'] = addr.is_global

        # filter out stuff without ipv4 addresses
        L = [_ for _ in L if 'ipv4' in _]
        return {'interfaces': L}

    def get_cpu_count():
        return len(os.sched_getaffinity(0))

    def get_mem_gb():
        return round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 2**30, 1)
else:
    assert 0

if __name__ == '__main__':
    root = pwd.getpwnam('root')
    print("Root user:   ", root)
    print("Root group:  ", grp.getgrgid(root.pw_gid))
    print("Useradd cmd: ", useradd_command('foo', True))
    print("Networking:  ", json.dumps(get_networking(), indent=2))
    print("CPUs:        ", get_cpu_count())
    print("RAM GB:      ", get_mem_gb())

#!/usr/bin/env python3

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

    def get_ip_addresses():
        d = {'private_ip': '127.0.0.1', 'public_ip': None}
        p = subprocess.run(['ipconfig', 'getifaddr', 'en0'], capture_output=True)
        assert p.returncode == 0, p
        ip = p.stdout.decode('utf8').strip()
        if ip and not ':' in ip:
            if ip.split('.')[0] in ('10', '192'):
                d['private_ip'] = ip
            else:
                d['public_ip'] = ip

        return d

elif sys.platform == 'linux':
    import pwd
    import grp

    def useradd_command(username, system=False):
        system = ' --system' if system else ''
        return f'useradd --user-group{system} {username}'

    def get_ip_addresses():
        d = {'private_ip': '127.0.0.1', 'public_ip': None}
        p = subprocess.run(['hostname', '-I'], capture_output=True)
        assert p.returncode == 0, p
        for ip in p.stdout.decode('utf8').strip().split():
            if ':' in ip:  # ipv6
                continue

            octet0 = ip.split('.')[0]
            if octet0 in ('127', '172'):
                continue

            if octet0 in ('10', '192'):
                d['private_ip'] = ip
            else:
                d['public_ip'] = ip

        return d
else:
    assert 0

if __name__ == '__main__':
    root = pwd.getpwnam('root')
    print(root)
    print(grp.getgrgid(root.pw_gid))
    print(useradd_command('foo', True))
    print(get_ip_addresses())

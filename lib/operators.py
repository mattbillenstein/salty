import os
import os.path
import shutil
import stat
import subprocess
import time
import traceback

import mako.exceptions
import mako.template

from .compat import pwd, useradd_command, usergroups_command
from .util import hash_data, hash_file, elapsed

DEFAULT_USER = pwd.getpwuid(os.getuid()).pw_name

# convenience imports used in roles and mako
IMPORTS = [
    'import os',
    'import os.path',
    'import json',
]

def run(content, context, start, PATH, get_file, syncdir_get_file, syncdir_scandir, server_shell):
    # these are the operators available in roles, they're nested functions here
    # so we can keep their signatures clean and collect the result of each
    # function...
    results = []
    context = dict(context)

    def my_ip(key='ipv4', filter='is_private'):
        network = None
        if filter == 'is_private':
            filter = context['me']['vars'].get('private_filter', filter)
            network = context['me']['vars'].get('private_network')

        L = [
            _ for _ in context['me']['facts']['networking']['interfaces']
            if _[filter] and (not network or _[key + '_network'] == network)
        ]
        assert L, f'Missing ip address for {key} {filter}'
        if len(L) > 1:
            print(f'Warning: Found multiple ip addresses for {key} {filter} {L}')
            L.sort(key=lambda x: x[key])

        return L[0][key]

    context['my_ip'] = my_ip

    def get_ips(role, key='ipv4', filter='is_private'):
        # return ip addresses of hosts serving the role in the same
        # cluster...

        # filter by host private network if set, otherwise we'll just get the
        # first private ip
        network = None
        if filter == 'is_private':
            filter = context['me']['vars'].get('private_filter', filter)
            network = context['me']['vars'].get('private_network')

        ips = []
        cluster = context['me']['cluster']
        for id, h in context['hosts'].items():
            if h['cluster'] == cluster and role in h['roles']:
                L = [
                    _ for _ in h['facts']['networking']['interfaces']
                    if _[filter] and (not network or _[key + '_network'] == network)
                ]
                assert L, f'Missing ip address for role {role} {key} {filter}'
                if len(L) > 1:
                    print(f'Warning: Found multiple ip addresses for role {role} {key} {filter} {L}')
                    L.sort(key=lambda x: x[key])
                ips.append(L[0][key])
        ips.sort()
        return ips

    context['get_ips'] = get_ips

    def _set_user_and_mode(path, user=DEFAULT_USER, mode=None):
        changed = False

        st = os.stat(path)

        if mode is None:
            mode = 0o644
            if stat.S_ISDIR(st.st_mode):
                mode = 0o755

        # We care about the group sticky bit and the standard permission
        # bits...
        if st.st_mode & (stat.S_ISGID | 0o777) != mode:
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
            path = PATH + path

            if not os.path.isdir(path):
                os.makedirs(path, mode=mode)
                result['created'] = True
                result['changed'] = True

            if _set_user_and_mode(path, user, mode):
                result['changed'] = True
        except Exception:
            result['rc'] = 1
            result['error'] = traceback.format_exc()

        result['elapsed'] = elapsed(start)
        return result

    def remove(path):
        start = time.time()
        result = {'cmd': f'remove({path})', 'rc': 0, 'changed': False, 'created': False, 'removed': False}
        results.append(result)
        try:
            path = PATH + path

            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                result['removed'] = True
                result['changed'] = True

        except Exception:
            result['rc'] = 1
            result['error'] = traceback.format_exc()

        result['elapsed'] = elapsed(start)
        return result

    def copy(src, dst, user=DEFAULT_USER, mode=0o644):
        start = time.time()
        result = {'cmd': f'copy({src}, {dst})', 'rc': 0, 'changed': False}
        results.append(result)
        try:
            dst = PATH + dst
            hash = hash_file(dst)
            result['created'] = hash is None

            res = get_file(src, hash=hash)
            assert not res.get('error'), res['error']

            if res['hash'] != hash:
                result['changed'] = True
                os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                with open(dst, 'wb') as f:
                    f.write(res['data'])

            if _set_user_and_mode(dst, user, mode):
                result['changed'] = True
        except Exception:
            result['rc'] = 1
            result['error'] = traceback.format_exc()

        result['elapsed'] = elapsed(start)
        return result

    def render(src, dst, user=DEFAULT_USER, mode=0o644, **kw):
        start = time.time()
        result = {'cmd': f'render({src}, {dst})', 'rc': 0, 'changed': False}
        results.append(result)

        try:
            dst = PATH + dst
            hash = hash_file(dst)
            result['created'] = hash is None

            res = get_file(src, hash=hash)
            assert not res.get('error'), res['error']

            # if the template has no template directives, the hash could
            # already match...
            if res['hash'] != hash:
                template = res['data'].decode('utf8')
                try:
                    data = mako.template.Template(template, imports=IMPORTS).render(**context, **kw).encode('utf8')
                except Exception:
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
        except Exception:
            result['rc'] = 1
            result['error'] = traceback.format_exc()

        result['elapsed'] = elapsed(start)
        return result

    def line_in_file(line, path, user=DEFAULT_USER, mode=0o644, replace=''):
        start = time.time()
        result = {'cmd': f'line_in_file({path}, {line}, replace="{replace}")', 'rc': 0, 'changed': False, 'created': False}
        results.append(result)

        try:
            path = PATH + path
            if os.path.isfile(path):
                with open(path, 'r') as f:
                    lines = f.readlines()
            else:
                result['created'] = True
                lines = []
                os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)

            # kinda messy, but we want to make sure the given line is on a full
            # line by itself, so make sure each line is terminated with a unix
            # newline - I'm ignoring \r\n and \r with no intention of
            # supporting Windows or Mac style text files...
            if lines and not lines[-1].endswith('\n'):
                lines[-1] += '\n'

            # match and replace a complete line, otherwise we append
            line += '\n'
            replace += '\n'

            if line not in lines:
                if replace.strip() and replace in lines:
                    lines[lines.index(replace)] = line
                else:
                    lines.append(line)

                with open(path, 'w') as f:
                    f.write(''.join(lines))

                result['changed'] = True

            if _set_user_and_mode(path, user, mode):
                result['changed'] = True
        except Exception:
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

        result['elapsed'] = elapsed(start)
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

    def usergroups(username, groups):
        start = time.time()
        result = {'cmd': f'usergroups({username}, {groups})', 'rc': 0, 'changed': False, 'created': False}
        results.append(result)

        cmd = usergroups_command(username, groups)
        if cmd:
            rc = shell(cmd)
            result['created'] = True
            result['changed'] = True
            result['output'] = rc['output']

        result['elapsed'] = elapsed(start)
        return result

    def syncdir(src, dst, user=DEFAULT_USER, mode=0o755, exclude=None):
        # add user and matching group if they do not exist
        start = time.time()
        result = {'cmd': f'syncdir({src}, {dst}, user={user})', 'rc': 0, 'changed': False, 'created': False}
        results.append(result)
        try:
            # lookup uid/gid once, pass this down to the main function
            user = pwd.getpwnam(user)

            dst = PATH + dst
            if not os.path.isdir(dst):
                os.makedirs(dst, mode=mode)
                result['created'] = True
                result['changed'] = True

            exclude = exclude or []
            if any(_.startswith(os.path.sep) for _ in exclude):
                raise Exception(f'Exclude starts with {os.path.sep} but is relative to src dir')

            srcs = syncdir_scandir(src, exclude=exclude)  # rpc
            dsts = syncdir_scandir_local(dst)
            changes = _syncdir(src, dst, user, srcs, dsts, syncdir_get_file)
            result['changed'] = result['changed'] or len(changes) > 0

            # condense changes from every file to a count...
            cngs = {'+': 0, '-': 0, '.': 0}
            for typ, path in changes:
                cngs[typ] += 1
            result['changes'] = cngs
        except Exception:
            result['rc'] = 1
            result['error'] = traceback.format_exc()

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
        'usergroups': usergroups,
        'syncdir': syncdir,
        'server_shell': server_shell,
    }
    g.update(context)
    content = '\n'.join(IMPORTS) + '\n' + content
    try:
        exec(content, g)
    except Exception:
        result = {'cmd': 'error in exec', 'rc': 1, 'changed': True}
        result['error'] = traceback.format_exc()
        results.append(result)

    return results, output

def syncdir_scandir_local(src, exclude=None):
    # scan directory and return metadata, on server and client
    exclude = exclude or []
    d = {}
    for entry in os.scandir(src):
        if entry.name in exclude:
            continue

        st = entry.stat(follow_symlinks=False)
        attrs = {
            'mode': st.st_mode & 0o777,
            'size': st.st_size,
            'mtime': st.st_mtime_ns,
            'uid': st.st_uid,
            'gid': st.st_gid,
        }

        # is_symlink has to come first because is_file is true for a symlink...
        if entry.is_symlink():
            attrs['type'] = 'link'
            attrs['target'] = os.readlink(os.path.join(src, entry.name))
        elif entry.is_file():
            attrs['type'] = 'file'
        elif entry.is_dir():
            # filter to matches on entry.name + '/' and then strip that prefix
            prefix = entry.name + os.path.sep
            nexclude = [_.replace(prefix, '', 1) for _ in exclude if _.startswith(prefix)]
            attrs['type'] = 'dir'
            attrs['entries'] = syncdir_scandir_local(os.path.join(src, entry.name), exclude=nexclude)
        else:
            raise Exception(f'Unrecognized type {src}/{entry.name}')

        d[entry.name] = attrs

    return d

def _syncdir_get_file(func, source, target):
    # this handles chunking across the wire
    with open(target, 'wb') as f:
        offset = 0
        while 1:
            x = func(source, offset=offset)
            f.write(x['data'])
            offset += len(x['data'])
            if offset == x['size']:
                break

def _syncdir(src, dst, user, srcs, dsts, syncdir_get_file):
    changes = []

    # delete first if not in src, or different type, then remove so we copy
    # later
    for dname in list(dsts):
        if dname not in srcs or \
                dsts[dname]['type'] != srcs[dname]['type'] or \
                srcs[dname]['type'] == 'link' and dsts[dname]['target'] != srcs[dname]['target']:
            target = os.path.join(dst, dname)
            dattrs = dsts.pop(dname)
            if dattrs['type'] == 'dir':
                shutil.rmtree(target)
            else:
                os.remove(target)
            changes.append(('-', target))

    for sname, sattrs in srcs.items():
        source = os.path.join(src, sname)
        target = os.path.join(dst, sname)

        dattrs = dsts.get(sname, {})
        if not dattrs:
            # create file/link/dir if it doesn't exists, set utime/chown/chmod
            changes.append(('+', target))
            if sattrs['type'] == 'file':
                _syncdir_get_file(syncdir_get_file, source, target)
                os.utime(target, ns=(sattrs['mtime'], sattrs['mtime']))
            elif sattrs['type'] == 'link':
                os.symlink(sattrs['target'], target)
            elif sattrs['type'] == 'dir':
                os.mkdir(target)

            os.chown(target, user.pw_uid, user.pw_gid, follow_symlinks=False)
            if sattrs['type'] != 'link':
                os.chmod(target, sattrs['mode'])

        elif dattrs['type'] == 'file' and any(dattrs[_] != sattrs[_] for _ in ('size', 'mtime')):
            # copy changed file on mtime / size mismatch, set utime/chown/chmod
            changes.append(('.', target))

            _syncdir_get_file(syncdir_get_file, source, target)

            os.utime(target, ns=(sattrs['mtime'], sattrs['mtime']))
            os.chown(target, user.pw_uid, user.pw_gid, follow_symlinks=False)
            if sattrs['type'] != 'link':
                os.chmod(target, sattrs['mode'])

        elif dattrs['uid'] != user.pw_uid or dattrs['gid'] != user.pw_gid:
            # owner change
            changes.append(('.', target))
            os.chown(target, user.pw_uid, user.pw_gid, follow_symlinks=False)

        elif sattrs['type'] != 'link' and dattrs['mode'] != sattrs['mode']:
            # permissions change
            changes.append(('.', target))
            os.chmod(target, sattrs['mode'])

        # lastly, recurse on directories
        if sattrs['type'] == 'dir':
            changes.extend(_syncdir(source, target, user, sattrs['entries'], dattrs.get('entries', {}), syncdir_get_file))

            # set mtime after we've sync'd, changes inside the dir change the
            # mtime...
            os.utime(target, ns=(sattrs['mtime'], sattrs['mtime']))

    return changes

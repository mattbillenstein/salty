import hashlib
import os
import os.path
import shutil
import stat
import subprocess
import time
import traceback

import mako.exceptions
import mako.template

from compat import grp, pwd, useradd_command

DEFAULT_USER = pwd.getpwuid(os.getuid()).pw_name

# convenience imports used in roles and mako
IMPORTS = [
    'import os',
    'import os.path',
    'import json',
]

def hash_data(data):
    return hashlib.sha1(data).hexdigest()

def hash_file(path):
    if os.path.isfile(path):
        with open(path, 'rb') as f:
            return hash_data(f.read())
    return None

def elapsed(start):
    return round(time.time() - start, 6)

def run(content, context, start, PATH, get_file):
    # these are the operators available in roles, they're nested functions here
    # so we can keep their signatures clean and collect the result of each
    # function...
    results = []
    context = dict(context)

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
            path = PATH + path

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
            path = PATH + path

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
            path = PATH + path
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
    content = '\n'.join(IMPORTS) + '\n' + content
    try:
        exec(content, g)
    except Exception as e:
        result = {'cmd': f'error in exec', 'rc': 1, 'changed': True}
        result['error'] = traceback.format_exc()
        results.append(result)

    return results, output

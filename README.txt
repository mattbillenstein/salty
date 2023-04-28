Salty - devops inspired by Saltstack, but simpler.

This is an experiment to see with how little code I could build a useful
SaltStack-like deployment system. As of Nov 2022, that is about 1050 LOC, and
I'm using it on a couple projects in production/staging/dev environments. It
supports Linux (primary tested on Ubuntu LTS) and MacOS using Python3.

It currently implements server/client over msgpack-rpc using gevent TLS/TCP
sockets, a simple request/response mechanism for triggering deployments across
a fleet of hosts, and an async file-server.

It uses simple Python (vs yaml) to define hosts and roles, clusters (groups of
hosts - ie prod, staging, etc), and environments (collections of vars that
apply to a host). The templating language is also Python (via Mako); so this is
probably the most complete Python all-in deployment system you can use. There
is very little to learn other than Python itself.

You interact with the system via the CLI by instantiating a client to send a
request to the server, typically via a shell script:

  $ cat bin/apply
  #!/bin/bash

  VERSION="$(git rev-parse HEAD)"
  sudo bash -c "source /opt/wve/bin/activate; /opt/w/salty/src/salty.py cli 127.0.0.1:11111 --keyroot=/opt/w/salty/keys type=apply skip=ve version=$VERSION $*"

By default it reports elapsed time, errors, and roles changed per host:

  $ bin/apply

  host:local.foo.dev elapsed:0.661 errors:0 changed:0

  elapsed:0.677

And we can get more verbose showing each role for each host as well:

  $ bin/apply -v

  host:local.foo.dev elapsed:0.651 errors:0 changed:0
    role:users       elapsed:0.001 errors:0 changed:0
    role:system      elapsed:0.003 errors:0 changed:0
    role:ve          elapsed:0.000 errors:0 changed:0
    role:dotfiles    elapsed:0.013 errors:0 changed:0
    role:src         elapsed:0.003 errors:0 changed:0
    role:postgres    elapsed:0.608 errors:0 changed:0
    role:redis       elapsed:0.003 errors:0 changed:0
    role:nginx       elapsed:0.011 errors:0 changed:0
    role:nsq         elapsed:0.000 errors:0 changed:0
    role:supervisord elapsed:0.009 errors:0 changed:0
    role:cleanup     elapsed:0.000 errors:0 changed:0

  elapsed:0.668

Roles are designed to be idempotent, so if a role is up to date, nothing is
changed. If we're more verbose, we can list all the steps for a role - here I'm
limiting to a single role for brevity:

  $ bin/apply -vv roles=nginx

  host:local.foo.dev elapsed:0.009 errors:0 changed:0
    role:users       elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:system      elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:ve          elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:dotfiles    elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:src         elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:postgres    elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:redis       elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:nginx       elapsed:0.009 errors:0 changed:0
      {'cmd': 'useradd(nginx, system=True)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 3.2e-05}
      {'cmd': 'makedirs(/opt/w/log/nginx, nginx, 0o755)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 2.5e-05}
      {'cmd': 'makedirs(/opt/w/run/nginx, nginx, 0o755)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 1.5e-05}
      {'cmd': 'makedirs(/opt/w/etc/ssl, nginx, 0o700)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 1.4e-05}
      {'cmd': 'copy(nginx/mime.types, /opt/w/etc/mime.types)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.000489}
      {'cmd': 'copy(nginx/ssl/dhparam.pem, /opt/w/etc/ssl/dhparam.pem)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.000441}
      {'cmd': 'render(nginx/nginx.conf, /opt/w/etc/nginx.conf)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.004856}
      {'cmd': 'render(nginx/event.lua, /opt/w/etc/event.lua)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.001625}
      {'cmd': 'copy(nginx/nginx.logrotate, /etc/logrotate.d/nginx)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.000417}
      {'cmd': 'copy(nginx/ssl/foo.dev.key, /opt/w/etc/ssl/foo.dev.key)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.000444}
      {'cmd': 'copy(nginx/ssl/foo.dev.cer, /opt/w/etc/ssl/foo.dev.cer)', 'rc': 0, 'changed': False, 'created': False, 'elapsed': 0.00045}
    role:nsq         elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:supervisord elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}
    role:cleanup     elapsed:0.000 errors:0 changed:0
      {'rc': 0, 'cmd': '...role skipped...', 'elapsed': 0.0, 'changed': False}

  elapsed:0.052

Every role except nginx was skipped, and now we can see all the steps for that
role, their runtime, and whether they were changed and created. rc is just a
'result code' in unix form where 0 is success and non-zero is failure.

One of the design goals is to be very fast - doing in seconds what takes
minutes in other systems by changing as little as is possible, and doing as
little actual work and I/O as possible.

See the example directory for a simple functioning example you can run locally.

Below is some simple documentation for what is currently available in writing
roles. I encourage you to consult the source in the "handle_run" method in
salty.py around:

  https://github.com/mattbillenstein/salty/blob/master/operators.py

Common Imports available in roles/templates:
  os, os.path, json

Functions available in roles:
  File management:
    copy(src, dst, user=DEFAULT_USER, mode=0o644):
      copy src file from server to dst path on client

    line_in_file(line, path, user=DEFAULT_USER, mode=0o644):
	  ensure given line is in file at path, create the file if it doesn't exist

    makedirs(path, user=DEFAULT_USER, mode=0o755):
      make all directories up to final directory denoted by path

    render(src, dst, user=DEFAULT_USER, mode=0o644, **kw):
      render src template from server to dst path on client

    symlink(src, dst):
      symlink src to dest on client

    syncdir(src, dst, user=DEFAULT_USER, mode=0o755):
      Synchronize a src dir on the server to the dst dir on the client - ala
      rsync

  Shell commands:
    shell(cmds, **kw)
      Run a string of shell commands, **kw are optional Popen kwargs

  User management:
    useradd(username, system=False)
      Add a user and group of same name

  Misc
    print(s)
      Captures output for the role run response

    is_changed()
      True if command in the current role has changed

    get_ips(role, key='private_ip')
      get a list of ip addresses by role

Context available in templates:
  id:
    current host id

  me:
    host metadata of current host - ie, the contents of hosts[id]

  role:
    current role being executed

  hosts:
    other hosts in the cluster keyed by host id, metadata includes:
      env: host's environment 'dev', 'prod', etc
      cluster: name of host's cluster
      facts: collected facts for host, kernel, arch, ip addresses, etc
      vars: collected env/cluster variables for host

  bootstrap:
	True/False if we're in bootstrap mode - ie, init is not running yet, skip
    service restarts, etc

  version:
    Current git HEAD

  get_ips(role, key='private_ip'):
    get a list of ip addresses by role

Crypto:
  The PASSWORD var here would be the contents of your crypto.pass as read by
  salty, so you could use the shell:
    PASSWORD=$(sudo cat /path/to/salty/crypto.pass) ./crypto.py ...

  Encrypt string for env/cluster vars:
    PASSWORD=... ./crypto.py es '<string>'
  Decrypt string for env/cluster vars:
    PASSWORD=... ./crypto.py ds '<string>'

  Encrypt file for files/<role>/<filename.ext>.enc
    PASSWORD=... ./crypto.py e filename [more filenames]
  Decrypt file for files/<role>/<filename.ext>.enc
    PASSWORD=... ./crypto.py d filename [more filenames]

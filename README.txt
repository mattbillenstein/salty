Salty - inspired by Saltstack, but simpler.

See the example directory for usage.

This is a simple prototype - do not use this anywhere for anything...

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

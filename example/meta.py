
clusters = {
    'local': {
        'domains': ['local.foo.dev'],
    },
}

# HOSTS
hosts = {
    'local': {},
}

for _i in range(10):
    hosts['local'][f'server{_i}'] = {
      'env': 'dev',
      'roles': ['role1', 'supervisord'],
    }

# ENVS

_common_env = {
    'hi': 'there',
}

envs = {
    'dev': {
        'the': 'rain in spain',

    # encrypted secrets can be put here
    #    'secret': 'NACL[ ... ../cryto.py es "some secret" ]'
        'secret': 'NACL[TGE10k69Sb-EA-N6hWCIkeJpTfCkxpYePFWFy6EeWHVkBCrYJg7nUrSiiXaWg_UM]',
    },
}

# merge _common env, but don't overwrite redefined keys...
for _k in ("dev",):
    _d = envs[_k]
    for _k2, _v2 in _common_env.items():
        if _k2 not in _d:
            _d[_k2] = _v2

# servers are keyed by cluster

local = {}

for _i in range(10):
    local[f'server{_i}'] = {
      'env': 'dev',
      'roles': ['role1', 'supervisord'],
    }

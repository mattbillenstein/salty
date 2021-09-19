# files are rooted in the 'files' dir
x = copy('role1/afile.txt', '/etc/afile.txt')
if x['changed']:
  render('role1/atemplate.txt', '/etc/atemplate.txt', extra='some extra data')

# it's just python, so go wild
for i in range(3):
  copy('role1/afile.txt', f'/etc/afile{i}.txt')

# and you can run shell on the remote
shell('''
echo "The date is $(date)"
''')

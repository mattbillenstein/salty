makedirs('/opt/data/run')
makedirs('/opt/log')

conf = render('supervisord/supervisord.conf', '/opt/etc/supervisord.conf')
if not bootstrap and conf['changed']:
    shell('echo supervisorctl -c /opt/etc/supervisord.conf update')

if os.path.isdir('/lib/systemd/system'):
    copy('supervisord/systemd/supervisord.service', '/lib/systemd/system/supervisord.service')
    if bootstrap:
        shell('echo systemctl enable supervisord')
        shell('echo systemctl start supervisord')

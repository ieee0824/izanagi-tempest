#!/bin/sh
# Trusted Packer provisioning only; no benchmark setup or credentials are baked in.
set -eu
umask 077
stage=/tmp/tempest-m3
id izanagi >/dev/null
if ! id lws >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /var/lib/lws --shell /usr/sbin/nologin lws
fi
lws_uid=$(id -u lws)
lws_gid=$(id -g lws)
test "$lws_uid" != 0
test "$lws_uid" != "$(id -u izanagi)"
install -d -o root -g root -m 0755 /etc/tempest /usr/local/libexec
install -o root -g root -m 0755 "$stage/lws" /usr/local/bin/lws
install -o root -g root -m 0755 "$stage/tempest-guest" /usr/local/libexec/tempest-guest-native
install -o root -g root -m 0755 "$stage/dispatcher.py" /usr/local/bin/tempest-guest
install -o root -g root -m 0755 "$stage/dispatcher.py" /usr/local/libexec/tempest-mailbox
install -d -o lws -g lws -m 0700 /var/lib/lws /var/lib/tempest
python3 - "$stage/image.json" "$lws_uid" "$lws_gid" <<'PY'
import json,sys,subprocess,hashlib
from pathlib import Path
uid,gid=map(int,sys.argv[2:])
config={'state_dir':'/run/tempest-control','data_dir':'/var/lib/lws','evidence_dir':'/var/lib/tempest',
        'listen':'127.0.0.1:4566','upstream':'127.0.0.1:4567','lws':'/usr/local/bin/lws',
        'aws':subprocess.check_output(['which','aws'],text=True).strip(),
        'tcpdump':subprocess.check_output(['which','tcpdump'],text=True).strip(),
        'capture_interface':'lo','service_uid':uid,'service_gid':gid,'development':False,'timeout_seconds':30}
p=Path('/etc/tempest/guest.json');p.write_text(json.dumps(config,indent=2)+'\n');p.chmod(0o644)
metadata=json.loads(Path(sys.argv[1]).read_text())
metadata['service_uid']=uid;metadata['service_gid']=gid
metadata['packages']={name:subprocess.check_output(['dpkg-query','-W','-f=${Version}',name],text=True).strip()
                      for name in ['awscli','tcpdump','iptables','opendoas','python3','python3-cryptography']}
metadata['installed_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                            map(Path,['/usr/local/bin/lws','/usr/local/libexec/tempest-guest-native','/usr/local/bin/tempest-guest','/usr/local/libexec/tempest-mailbox'])}
p=Path('/etc/tempest/image.json');p.write_text(json.dumps(metadata,indent=2)+'\n');p.chmod(0o644)
PY
cat > /etc/doas.conf <<'DOAS'
permit nopass izanagi as root cmd /usr/local/bin/tempest-guest
DOAS
chown root:root /etc/doas.conf
chmod 0600 /etc/doas.conf
# Only the fixed dispatcher is delegated. It rejects arbitrary commands/config paths.
cat > /usr/local/libexec/tempest-firewall <<'FIREWALL'
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
iptables -w -N TEMPEST_BACKEND 2>/dev/null || iptables -w -L TEMPEST_BACKEND >/dev/null
# Bind the private chain only to loopback TCP backend traffic.
iptables -w -C OUTPUT -o lo -p tcp -d 127.0.0.1 --dport 4567 -j TEMPEST_BACKEND 2>/dev/null || \
  iptables -w -I OUTPUT 1 -o lo -p tcp -d 127.0.0.1 --dport 4567 -j TEMPEST_BACKEND
iptables -w -F TEMPEST_BACKEND
iptables -w -A TEMPEST_BACKEND -m owner --uid-owner 0 -j ACCEPT
iptables -w -A TEMPEST_BACKEND -m owner --uid-owner lws -j ACCEPT
iptables -w -A TEMPEST_BACKEND -p tcp -j REJECT --reject-with tcp-reset
FIREWALL
chmod 0755 /usr/local/libexec/tempest-firewall
cat > /etc/systemd/system/tempest-firewall.service <<'SERVICE'
[Unit]
Description=Tempest owner restriction for local LWS backend
After=local-fs.target
Before=tempest-control.service izanagi-agent.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/tempest-firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SERVICE
cat > /etc/systemd/system/tempest-control.service <<'SERVICE'
[Unit]
Description=Tempest root control supervisor (HTTP/capture start only on seal)
Requires=tempest-firewall.service
After=local-fs.target tempest-firewall.service
Before=izanagi-agent.service
[Service]
Type=exec
UMask=0077
ExecStart=/usr/local/libexec/tempest-guest-native --config /etc/tempest/guest.json recorder
Restart=no
TimeoutStopSec=45
[Install]
WantedBy=multi-user.target
SERVICE
install -d -m 0755 /etc/systemd/system/izanagi-agent.service.d
cat > /etc/systemd/system/izanagi-agent.service.d/tempest.conf <<'SERVICE'
[Unit]
Requires=tempest-control.service tempest-firewall.service
After=tempest-control.service tempest-firewall.service
SERVICE
cat > /etc/systemd/system/tempest-mailbox.service <<'SERVICE'
[Unit]
Description=Tempest root mailbox consumer
Requires=tempest-control.service
After=tempest-control.service
Before=izanagi-agent.service
[Service]
Type=exec
UMask=0077
ExecStart=/usr/local/libexec/tempest-mailbox --watch
Restart=no
[Install]
WantedBy=multi-user.target
SERVICE
cat >> /etc/systemd/system/izanagi-agent.service.d/tempest.conf <<'SERVICE'
Requires=tempest-mailbox.service
After=tempest-mailbox.service
SERVICE
# Build assets contain executables/metadata only; no scenario or run credential.
rm -f "$stage/lws" "$stage/tempest-guest" "$stage/dispatcher.py" "$stage/image.json"
systemctl daemon-reload
systemctl enable tempest-firewall.service tempest-control.service tempest-mailbox.service
# Fail the build with the exact firewall diagnostic, before removing SSH access.
sh -x /usr/local/libexec/tempest-firewall
systemctl start tempest-firewall.service || { journalctl -u tempest-firewall.service --no-pager; exit 1; }

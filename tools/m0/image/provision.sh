#!/bin/sh
# Runs only while building an M0 investigation image, before upstream lock-down.
set -eu
install -d -m 0755 /etc/tempest-m0
cat > /etc/systemd/system/tempest-m0-capture.service <<'SERVICE'
[Unit]
Description=Tempest M0 loopback capture and startup marker
After=local-fs.target
Before=izanagi-agent.service
[Service]
Type=simple
UMask=0022
ExecStartPre=/usr/bin/install -d -m 0755 /run/tempest-m0
ExecStartPre=/bin/sh -c 'id -u > /run/tempest-m0/startup.uid; date +%%s%%N > /run/tempest-m0/startup.epoch'
ExecStart=/usr/bin/tcpdump -Z root -i lo -U -w /run/tempest-m0/loopback.pcap
Restart=on-failure
[Install]
WantedBy=multi-user.target
SERVICE
# Debian installs tcpdump in /usr/bin or /usr/sbin, depending on package version.
tcpdump_path=$(command -v tcpdump)
sed -i "s|ExecStart=/usr/bin/tcpdump |ExecStart=$tcpdump_path |" /etc/systemd/system/tempest-m0-capture.service
systemctl daemon-reload
systemctl enable tempest-m0-capture.service

# Optional fixed root backend, used only to prove UID-based connection rejection.
if [ -f /usr/local/bin/tempest-m0-lws ]; then
  chown root:root /usr/local/bin/tempest-m0-lws
  chmod 0755 /usr/local/bin/tempest-m0-lws
  iptables_path=$(command -v iptables)
  cat > /etc/systemd/system/tempest-m0-firewall.service <<SERVICE
[Unit]
Description=Tempest M0 root-only backend port
Before=tempest-m0-backend.service izanagi-agent.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$iptables_path -A OUTPUT -o lo -p tcp -d 127.0.0.1 --dport 4567 -m owner ! --uid-owner 0 -j REJECT
SERVICE
  cat > /etc/systemd/system/tempest-m0-backend.service <<'SERVICE'
[Unit]
Description=Tempest M0 strict LWS backend for connection rejection test
Requires=tempest-m0-firewall.service
After=tempest-m0-firewall.service network.target
Before=izanagi-agent.service
[Service]
Type=simple
Environment=LWS_BIND_ADDR=127.0.0.1:4567
Environment=LWS_AUTH_MODE=strict
Environment=LWS_ROOT_ACCESS_KEY_ID=tempest-m0-dummy-backend-admin
Environment=LWS_DATA_DIR=/var/lib/tempest-m0/backend
ExecStartPre=/usr/bin/install -d -m 0700 /var/lib/tempest-m0/backend
ExecStartPre=/usr/bin/install -d -m 0755 /run/tempest-m0
ExecStart=/usr/local/bin/tempest-m0-lws
ExecStartPost=/bin/sh -c 'for n in 1 2 3 4 5 6 7 8 9 10; do curl --noproxy "*" --max-time 1 -fsS http://127.0.0.1:4567/_lws/health > /run/tempest-m0/backend-health.json && exit 0; sleep 0.2; done; exit 1'
Restart=on-failure
[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
  systemctl enable tempest-m0-backend.service
fi

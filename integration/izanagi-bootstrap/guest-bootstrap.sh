#!/bin/sh
set -eu
# The pinned upstream Alpine template does not create the Exec identity.
if grep -q '^izanagi:' /etc/passwd || grep -q '^izanagi:' /etc/group; then
  echo 'unexpected existing bootstrap identity' >&2
  exit 1
fi
if awk -F: '$3 == 1000 {found=1} END {exit !found}' /etc/passwd ||
   awk -F: '$3 == 1000 {found=1} END {exit !found}' /etc/group; then
  echo 'bootstrap UID/GID already allocated' >&2
  exit 1
fi
addgroup -g 1000 izanagi
adduser -D -u 1000 -G izanagi -s /sbin/nologin izanagi
# adduser -D already creates a locked password. BusyBox passwd -l returns
# failure for an already locked account; verify state without printing hashes.
awk -F: '$1 == "izanagi" { found++; if ($2 !~ /^[!*]/) bad=1 } END { exit !(found == 1 && !bad) }' /etc/shadow
test "$(id -u izanagi)" = 1000
test "$(id -g izanagi)" = 1000
test -x /usr/bin/id
# The upstream agent fails closed without an explicit command allowlist.
# OpenRC loads this service-specific configuration before starting the agent.
test -d /etc/conf.d
test ! -e /etc/conf.d/izanagi-agent
test ! -L /etc/conf.d/izanagi-agent
printf '%s\n' 'export IZANAGI_ALLOWED_COMMANDS=/usr/bin/id' > /etc/conf.d/izanagi-agent
chown root:root /etc/conf.d/izanagi-agent
chmod 0644 /etc/conf.d/izanagi-agent
# Check module availability during preparation; persist load for the next boot.
modprobe qemu_fw_cfg
grep -qxF qemu_fw_cfg /etc/modules || printf '%s\n' qemu_fw_cfg >> /etc/modules

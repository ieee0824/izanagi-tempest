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
passwd -l izanagi
test "$(id -u izanagi)" = 1000
test "$(id -g izanagi)" = 1000
test -x /usr/bin/id
# Check module availability during preparation; persist load for the next boot.
modprobe qemu_fw_cfg
grep -qxF qemu_fw_cfg /etc/modules || printf '%s\n' qemu_fw_cfg >> /etc/modules

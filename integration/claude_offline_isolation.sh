#!/usr/bin/env bash
# 固定 Linux x86_64 CLI の合成設定と OS 隔離を比較する。
set -euo pipefail

source_claude=$(realpath "${1:?固定 Claude CLI のパスを指定してください}")
digest=0dc4f4a9a165fc60746d7ae8489712e5fc352f1e7ad4eb22e7141bd0812eb0cf
test "$(uname -m)" = x86_64
test "$(id -u)" -ne 0
sudo -n true

evidence=$(mktemp -d /var/tmp/tempest-claude-isolation.XXXXXX)
printf '証跡: %s\n' "$evidence"
control=$evidence/control
root=$evidence/root
cleanup() {
    sudo -n rm -rf -- "$root" "$control"
    test ! -e "$root" && test ! -e "$control"
}
trap cleanup EXIT

mkdir -p "$control"/{home,config,tmp,work/.claude,probe}
mkdir -p "$root"/{bin,home,config,tmp,work,etc,proc,dev,probe}
chmod 1777 "$root/tmp"
claude=$root/bin/claude
cp "$source_claude" "$claude"
chmod 0555 "$claude"
printf '%s  %s\n' "$digest" "$claude" | sha256sum --check
cp /usr/bin/busybox "$root/bin/busybox"
ldd "$claude" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' |
    sort -u | while IFS= read -r library; do cp -L --parents "$library" "$root"; done
printf '{}\n' > "$control/config/settings.json"
printf '{}\n' > "$control/work/.claude/settings.json"
printf '{}\n' > "$control/work/.claude/settings.local.json"
cp "$control/config/settings.json" "$root/config/settings.json"

cat > "$root/probe/run" <<'PROBE'
echo started >> "$1"
while IFS= read -r line; do
    case "$line" in
        *'"method":"initialize"'*)
            echo initialize >> "$1"
            printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"offline-probe","version":"1"}}}'
            ;;
        *'"method":"notifications/initialized"'*) echo initialized >> "$1" ;;
    esac
done
PROBE
cp "$root/probe/run" "$control/probe/run"
printf '{"mcpServers":{"probe":{"command":"/usr/bin/busybox","args":["sh","%s/probe/run","%s/tmp/probe.events"]}}}\n' "$control" "$control" > "$control/work/.mcp.json"
printf '{"mcpServers":{"probe":{"command":"/bin/busybox","args":["sh","/probe/run","/tmp/probe.events"]}}}\n' > "$root/config/mcp.json"

control_status=0
(cd "$control/work"
 sudo -n unshare --net -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups --no-new-privs \
     env -i PATH=/usr/bin:/bin HOME="$control/home" CLAUDE_CONFIG_DIR="$control/config" TMPDIR="$control/tmp" LC_ALL=C \
     timeout 20 strace -ff -s 400 -e trace=%file -o "$evidence/control.trace" \
     "$claude" --print 'Offline diagnostic only' </dev/null
) > "$evidence/control.out" 2>&1 || control_status=$?
test "$control_status" -eq 1
grep -Fq 'Not logged in' "$evidence/control.out"
for file in "$control/config/settings.json" "$control/work/.claude/settings.json" "$control/work/.claude/settings.local.json" "$control/work/.mcp.json"; do
    grep -F "\"$file\", O_RDONLY" "$evidence"/control.trace.* | grep -v O_PATH | grep -E " = [0-9]+$" > /dev/null
done
grep -Fxq started "$control/tmp/probe.events"
cp "$control/tmp/probe.events" "$evidence/control.events"

isolated_status=0
sudo -n unshare --mount --propagation private --pid --fork --kill-child --net /bin/sh -eu -c '
    mount -t proc proc "$1/proc"
    touch "$1/dev/null"
    mount --bind /dev/null "$1/dev/null"
    cat /proc/net/route > "$2/isolated.routes"
    cat /proc/net/dev > "$2/isolated.interfaces"
    exec strace -ff -s 400 -e trace=%file -o "$2/isolated.trace" timeout 20 \
        chroot --userspec="$3" --groups="" "$1" /bin/busybox env -i \
        PATH=/bin HOME=/home CLAUDE_CONFIG_DIR=/config TMPDIR=/tmp LC_ALL=C \
        /bin/busybox sh -eu -c '"'"'
            cd /work
            test ! -e "$1/config/settings.json"
            test ! -e "$1/work/.claude/settings.json"
            test ! -e "$1/work/.claude/settings.local.json"
            test ! -e "$1/work/.mcp.json"
            echo ordinary-config-absent
            exec /bin/claude --setting-sources "" --strict-mcp-config --mcp-config /config/mcp.json --print "Offline diagnostic only"
        '"'"' sh "$4"
' sh "$root" "$evidence" "$(id -u):$(id -g)" "$control" </dev/null > "$evidence/isolated.out" 2>&1 || isolated_status=$?

test "$isolated_status" -eq 1
grep -Fxq ordinary-config-absent "$evidence/isolated.out"
grep -Fq 'Not logged in' "$evidence/isolated.out"
test "$(awk 'NR > 1 { n++ } END { print n+0 }' "$evidence/isolated.routes")" -eq 0
test "$(awk -F: 'NR > 2 { gsub(/ /, "", $1); print $1 }' "$evidence/isolated.interfaces")" = lo
printf 'started\ninitialize\ninitialized\n' | cmp - "$root/tmp/probe.events"
cp "$root/tmp/probe.events" "$evidence/isolated.events"
cleanup
trap - EXIT
printf 'cleanup-ok\n' | tee "$evidence/cleanup"

# Linux x86 image smoke002 計画

## 状態と固定対象

計画レビュー用。snapshot 作成・UID999 の準備検査は完了、VM は未起動。
unit は tempest-izanagi-image-smoke-002.service、root は /var/lib/tempest-izanagi-image-smoke-002。
旧001/v1/v2、full-build001/002/003、offline001 の入力と証拠は保持し、再利用して起動しない。
image は full003 SHA5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e、CLI は SHA088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8 を維持する。
core、guest image、package の追加変更はない。

## 初回からの変更

[offline001](LINUX_X86_IMAGE_OFFLINE_001.md) の監査済 report を inputs/offline-artifacts.json として固定する。
image/artifact_evidence.py を Python import closure に追加する。
image SHA前後・固定3path/hash/ELF/root owner/mode と actor read境界を照合する。
agent/eBPF は EACCES、HTTP は読取成功/hash一致を必須にする。
root-only agent ldd は未検証と記録し、claim 後に既存 attest の実 agent hash を別途照合する。
observer は --attempt 002 で固定unit/rootを選び、QEMU stat identity bracket 内の cwd を照合する。
path=. は当該 workspace cwd の場合だけ許可する。旧001の観測を遡って合格にしない。

## snapshot と実行前検査

root:tempest-kvm の read-only inputs を新規作成し、全file SHA/mode/owner、directory、symlink target、外部runtimeを公開メタデータへ記録する。
venv は新prefixで固定wheelからoffline構築し、UID999で import/version/AES roundtrip/--help と readable/nonwritable を確認する。
work/home,tmp,evidence は UID999/0700。output、exit-status、caller/observer log は未作成・非symlinkを検査する。
unit未使用、UID999/QEMU残留なし、KVM境界、旧入力不変、空き容量、host bootID を確認する。
exec recorder は002専用unit/pathに導出し、O_EXCL/NOFOLLOWで exit evidence を保存する。

## 単発実行

[review用unit](../integration/tempest-izanagi-image-smoke-002.service) を参照する。install/enableはしない。
root read-only observer を先行する:

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-image-smoke-002/inputs/repo/integration/image_smoke_observe.py --attempt 002 --output /tmp/tempest-image-smoke-observation-002.jsonl
```

snapshot metadata と最終 command のレビュー後に、unit定義と同一の property/ExecStart/ExecStopPost を systemd-run --wait --pipe で一度実行する。
caller log は /tmp/tempest-image-smoke-002.log に private/noclobber で記録する。
Type=exec/User999/Group988/SupplementaryGroups=kvm/KillMode=control-group/RuntimeMaxSec1800/TimeoutStopSec10/Restart=no/UMask0077/NoNewPrivileges=yes/Delegate=no。
Python -I -B/env-i で ambient credentials を排除し、run独立dummy HMACを生成する。
--tempest と delivery-race fixture は指定しない。

## 成功範囲と停止

既存M3の owner/mapped-xattr/readonly/private mailbox/doas/fw_cfg/proc/cgroup/firewall、claim/seed、dummy LWS200/403/501、並行ciphertext、子process境界、export barrier、dummy HTTP/API/PCAP、実nonce/PID/pathのopen eventを検査する。
sidecar実起動、独立Rust MCP route、forced delivery race、二run reset、正式モデル比較は未証明のまま残す。外部到達拒否と正常 positive control の組も未証明であり、既存 firewall / API / PCAP 検査と区別する。実AWSは使わない。
observer異常/失敗/期限超過は当該unitだけ停止回収し、部分証拠を保持する。別retryや権限緩和、tracer無効化で合格にしない。
caller終端、unit最終状態、exit recorder、trusted journal、cgroup/UID999/agent port回収を別々に確認する。
正常時も image/inputs/旧証拠不変を確認し、公開は選別結果/hashのみ。dummy keyは結果照合後に削除し値/hashを公開しない。

## 固定準備の実測

[全1306入力](LINUX_X86_IMAGE_SMOKE_SNAPSHOT_002.json) と [UID999準備検査](LINUX_X86_IMAGE_SMOKE_PREPARATION_002.json) を保存した。
input rows SHA256 は 45f58b03a569e99d8aecb095f4daf30c26b0ead1b157e1bd5711b01c371314ee。
[作成 helper](evidence/image-smoke-002/prepare_snapshot.py) と [検査 helper](evidence/image-smoke-002/check_preparation.py) も保存した。
作成 caller70116 と検査 caller24273 は、それぞれ同handleで終端exit0を確認した。
専用userによる全input read可能/write不可、global runtime SHA一致、prefix/version/AES、--help、private work、xattr roundtripを確認した。
unitはnot-found/inactive/Invocation空、準備検査終了後UID999 processなし、free44276301824 bytesだった。
この値は実行直前に再確認する。snapshotのimage/core/CLIは従前と同一で、offline reportと新moduleを追加した。

実 systemd-run argv は [固定 caller](evidence/image-smoke-002/run_once.py) の COMMAND に保存した。現在は未実行。observer は上記固定 command を先行し、caller はこの script を Python -I -B で一度だけ呼ぶ。

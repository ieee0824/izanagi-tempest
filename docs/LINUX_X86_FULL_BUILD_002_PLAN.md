# Linux x86 full image build002 準備案

room #16493 に沿う診断目的の次試行案。実行していない。[前試行の失敗と回収](LINUX_X86_FULL_BUILD_001.md)を保持し、原因修正成功とは扱わない。旧 Alpine build/boot 入力と証拠は変更しない。

## 入力と snapshot

[準備記録](LINUX_X86_FULL_PREPARATION.md)と[artifact manifest](LINUX_X86_FULL_ARTIFACTS.json)の全成功を確認した後、実 `image/prepare.py --architecture x86_64` を新 private `/tmp/tempest-x86-image-definition-002` に実行する。定義内の入力は生成物の実 SHA と照合する。既存 Packer 1.15.0/plugin 1.1.8 の full validate まで確認する。

root snapshot の新 parent は `/var/lib/tempest-izanagi-full-build-002`。入力は root:tempest-kvm の directory 0750、通常 file 0440、Packer/plugin executable 0550 とする。ISO、5 artifacts、派生 definition、Packer、plugin と sidecar の全 hash/mode/owner を記録する。定義内の絶対入力 path と vars を snapshot 内へ置換し、manifest の path と template hash を更新、元 manifest SHA を別記する。置換後に専用 user の full validate を行う。

`work` とその `tmp/cache/home` は専用 uid 999 の 0700。入力 directory/file の user read 可・write 不可、source checkout clean、旧 snapshot/hash 不変、新 output 不在、専用 UID 残留なし、unit 未使用、18082/22222/5902 未使用を直前確認する。guest 用 GNU artifact の loader/GLIBC requirement の整合性を説明できない場合は実 build へ進まない。

## 観測と単発 command 案

observer は `--phase image --attempt 002` だけを新 unit に対応付ける。sample は unit cgroup の一致とその process に属する socket を検査し、Invocation の変更、非 loopback listener、GC による terminal 証拠欠落を失敗として扱う。

```sh
sudo -n /usr/bin/python3 /var/lib/tempest-izanagi-full-build-002/inputs/observe.py --phase image --attempt 002 --output /tmp/tempest-x86-full-build-observation-002.jsonl
```

実行時の caller stdout/stderr は新 private log に保存する。以下は未実行の単発案。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-image-002 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-full-build-002/work \
  /usr/bin/env -i PATH=/usr/bin:/bin \
  HOME=/var/lib/tempest-izanagi-full-build-002/work/home \
  TMPDIR=/var/lib/tempest-izanagi-full-build-002/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-full-build-002/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-full-build-002/inputs/plugins \
  CHECKPOINT_DISABLE=1 PACKER_LOG=1 \
  PACKER_LOG_PATH=/var/lib/tempest-izanagi-full-build-002/work/packer-debug.log \
  /var/lib/tempest-izanagi-full-build-002/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-full-build-002/inputs/definition/packer/tempest.pkrvars.json \
  /var/lib/tempest-izanagi-full-build-002/inputs/definition/packer/debian.pkr.hcl
```

期限・異常時の stop/kill はこの unit のみ。終了は caller exit、同 Invocation の trusted journal と service metadata、cgroup/UID/socket 回収、入力不変、guest lock-down/verify、新 image SHA を別々に照合する。GC による observer 非0を成功へ変換せず unknown と記録し、独立した証拠を照合する。失敗は原因を報告し、無断再試行・VM boot・livecall へ進まない。

## 診断差分と snapshot 実測

9d57089 の差分は `-serial file:installer-serial.log`、`console=tty0 console=ttyS0,115200n8`、quiet 除去、observer image002 対応。auto=true/priority=critical/preseed URL は維持しており、前試行の原因を修正できたとは扱わない。

新 definition002 を実 production derive/prepare で生成し、固定 Packer の full validate は exit0。新 root snapshot002 の[26 file SHA/mode/owner](LINUX_X86_FULL_SNAPSHOT_002.json)を実 bytes と再照合し、uid999 で全 input readable/nonwritable、work/home/tmp/cache0700 writable を確認した。専用 user env-i/snapshot Packer/plugin の full validate も exit0。元 manifest SHA を保持し、5artifact/ISO は前試行と同 SHA、guest source tree dirtyfalse。

旧 bootstrap snapshot001〜004とfull snapshot001の全記載 input SHA不変を作成前に検査した。旧full001 work/partial/evidenceは保持。新serial/debug/outputは不在/非symlinkを確認した。直前に再確認する。

ISO を mount/実行せず既存 ISO9660 reader で [isolinux.cfg/menu.cfg の実内容と SHA](LINUX_X86_ISOLINUX_CONFIG.json) を採取。isolinux.cfg は prompt0/timeout0/default vesamenu.c32、menu.cfg は BIOS mode と表示し複数 menu include を持つ。これだけで Packer の Esc/引数が正しく到達したことは証明しない。

起動後は同unitのWorkingDirectoryと実QEMU /proc/PID/cwdを照合し、serial/debugが新private work内の通常fileとして出ることを確認する。serialから実kernel command lineのauto/priority/preseed/console到達を選別記録し、debugからpreseed GET等を取得できれば記録する。未記録はGET未発生や引数不在の証明にはしない。debug原本はprivateのまま保持し、全argv/認証値/鍵や無関係な行をroom/modelへ流さない。

caller logは `/tmp/tempest-x86-full-build-002.log`、observerは上記新JSONL。新unit未使用/uid999none/3port空/26hash不変/残容量を直前再検査する。言語prompt等の無人進行不能を再確認した場合は手動入力せず新unitだけ停止、同Invocation terminal/独立回収/全入力不変/partialとログhashを保存する。実試行はこの具体計画の監査後。

準備時の確認: x86導出5tests、observer8testsが成功。新unit002はnot-found/inactive、uid999processなし、3port listenerなし、free59718619136 bytes。

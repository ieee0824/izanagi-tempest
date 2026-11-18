# Linux x86 full image build003 準備案

room #16503 に沿う試行003準備。実行していない。[前試行002の結果](LINUX_X86_FULL_BUILD_002.md)を保持し、待機時間変更の実受入は次の実行で確認する。

## 入力と snapshot

[準備記録](LINUX_X86_FULL_PREPARATION.md)と[artifact manifest](LINUX_X86_FULL_ARTIFACTS.json)の全成功を確認した後、実 `image/prepare.py --architecture x86_64` を新 private `/tmp/tempest-x86-image-definition-003` に実行する。定義内の入力は生成物の実 SHA と照合する。既存 Packer 1.15.0/plugin 1.1.8 の full validate まで確認する。

root snapshot の新 parent は `/var/lib/tempest-izanagi-full-build-003`。入力は root:tempest-kvm の directory 0750、通常 file 0440、Packer/plugin executable 0550 とする。ISO、5 artifacts、派生 definition、Packer、plugin と sidecar の全 hash/mode/owner を記録する。定義内の絶対入力 path と vars を snapshot 内へ置換し、manifest の path と template hash を更新、元 manifest SHA を別記する。置換後に専用 user の full validate を行う。

`work` とその `tmp/cache/home` は専用 uid 999 の 0700。入力 directory/file の user read 可・write 不可、source checkout clean、旧 snapshot/hash 不変、新 output 不在、専用 UID 残留なし、unit 未使用、18082/22222/5902 未使用を直前確認する。guest 用 GNU artifact の loader/GLIBC requirement の整合性を説明できない場合は実 build へ進まない。

## 観測と単発 command 案

observer は `--phase image --attempt 003` だけを新 unit に対応付ける。sample は unit cgroup の一致とその process に属する socket を検査し、Invocation の変更、非 loopback listener、GC による terminal 証拠欠落を失敗として扱う。

```sh
sudo -n /usr/bin/python3 /var/lib/tempest-izanagi-full-build-003/inputs/observe.py --phase image --attempt 003 --output /tmp/tempest-x86-full-build-observation-003.jsonl
```

実行時の caller stdout/stderr は新 private log に保存する。以下は未実行の単発案。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-image-003 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-full-build-003/work \
  /usr/bin/env -i PATH=/usr/bin:/bin \
  HOME=/var/lib/tempest-izanagi-full-build-003/work/home \
  TMPDIR=/var/lib/tempest-izanagi-full-build-003/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-full-build-003/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-full-build-003/inputs/plugins \
  CHECKPOINT_DISABLE=1 PACKER_LOG=1 \
  PACKER_LOG_PATH=/var/lib/tempest-izanagi-full-build-003/work/packer-debug.log \
  /var/lib/tempest-izanagi-full-build-003/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-full-build-003/inputs/definition/packer/tempest.pkrvars.json \
  /var/lib/tempest-izanagi-full-build-003/inputs/definition/packer/debian.pkr.hcl
```

期限・異常時の stop/kill はこの unit のみ。終了は caller exit、同 Invocation の trusted journal と service metadata、cgroup/UID/socket 回収、入力不変、guest lock-down/verify、新 image SHA を別々に照合する。GC による observer 非0を成功へ変換せず unknown と記録し、独立した証拠を照合する。失敗は原因を報告し、無断再試行・VM boot・livecall へ進まない。

## 修正と snapshot 実測

06ab58a の x86 専用変更でboot_wait60→10sとし、元arm64は60sを維持した。serial/console/debugは002と同じ。observerは明示image003を許可する。10sで初期menuへ間に合い、無人preseedへ進めることは未検証。

新definition003を実prepareで生成、同5artifact/ISOを固定し、新root snapshot003へ束縛した。[全26input hash/mode/owner](LINUX_X86_FULL_SNAPSHOT_003.json)を実bytesと照合し、uid999の全input readable/nonwritable、private work/home/tmp/cache0700を確認。専用user/env-i/snapshot Packer/plugin fullvalidate exit0。導出5tests/observer8tests成功。旧bootstrap001〜004/full001002 input SHAと旧full001002の全記録証拠SHAも不変。

## 初期menuと引数到達の観測

boot_wait10sに合わせ、observerの後、unit開始の直前に次のread-only framebuffer helperを別の有限プロセスとして先行する。

```sh
python3 /tmp/tempest-fullbuild-vnc-readonly-003-pre.py
```

helperは127.0.0.1:5902の接続を最大45秒待ち、接続後3秒待ってframebufferを1枚取得する。RFB handshake/SetPixelFormat/SetEncodings/FramebufferUpdateRequestのみで、キー/clipboard入力は送らない。helper timeoutはVM停止/再試行の指示とはしない。出力は新0700 `/tmp/tempest-x86-full-build-003-screen-pre/screen.png`、開始前に不在/非symlinkを確認する。単発helperの構文検査済みで、まだ起動していない。

helper SHA-256: `2e3b296b150f1e794bec1ce640a424d821ccda1a3912c64ee2a398c8750d8ce3`。

unit開始後、同Invocation/実QEMUcwdとWorkingDirectoryを照合、3loopback listener、通常file0600のserial/debugを確認する。frame取得/save時刻とdebugのQEMU exec/bootwait/Typing時刻を対応付ける。serialの実kernelcmdlineからauto/priority/preseed/consoleの到達を選別し、HTTP取得を観測できれば記録する。未記録を不存在にしない。raw debug/認証値/鍵/全argvはroom/modelへ出さない。

speech誤入力が解消したかと、installerが無人進行するかを区別する。順調なら同runのfullbuild完了まで監視し、診断成功だけで中断しない。入力待ちや異常で無人進行不能なら003unitだけstop/必要時限定killし、同Invocation終了・独立回収・全入力不変と全ログ/partial hashを保存する。手動入力/別retry/旧image再起動なし。生成image boot/認証/livecallは結果監査後。

直前に26hash/mode/owner、serial/debug/output/log/helper出力不在非symlink、新unit未使用/uid999none/3ports空/容量を再確認する。実003は具体計画の監査後。

準備時の実測はunit003 not-found/inactive、uid999 processなし、3port listenerなし、free58802688000 bytes。

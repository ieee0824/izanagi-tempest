# Linux x86 full image build001 準備案

room #16463 に沿った準備。実 build は未実行であり、以下は全 artifact/ABI/manifest と root snapshot の確定後に監査する command 案。旧 Alpine build/boot 入力と証拠は変更しない。

## 入力と snapshot

[準備記録](LINUX_X86_FULL_PREPARATION.md)と[artifact manifest](LINUX_X86_FULL_ARTIFACTS.json)の全成功を確認した後、実 `image/prepare.py --architecture x86_64` を新 private `/tmp/tempest-x86-image-definition-001` に実行する。定義内の入力は生成物の実 SHA と照合する。既存 Packer 1.15.0/plugin 1.1.8 の full validate まで確認する。

root snapshot の新 parent は `/var/lib/tempest-izanagi-full-build-001`。入力は root:tempest-kvm の directory 0750、通常 file 0440、Packer/plugin executable 0550 とする。ISO、5 artifacts、派生 definition、Packer、plugin と sidecar の全 hash/mode/owner を記録する。定義内の絶対入力 path と vars を snapshot 内へ置換し、manifest の path と template hash を更新、元 manifest SHA を別記する。置換後に専用 user の full validate を行う。

`work` とその `tmp/cache/home` は専用 uid 999 の 0700。入力 directory/file の user read 可・write 不可、source checkout clean、旧 snapshot/hash 不変、新 output 不在、専用 UID 残留なし、unit 未使用、18082/22222/5902 未使用を直前確認する。guest 用 GNU artifact の loader/GLIBC requirement の整合性を説明できない場合は実 build へ進まない。

## 観測と単発 command 案

observer は `--phase image --attempt 001` だけを新 unit に対応付ける。sample は unit cgroup の一致とその process に属する socket を検査し、Invocation の変更、非 loopback listener、GC による terminal 証拠欠落を失敗として扱う。

```sh
sudo -n /usr/bin/python3 integration/izanagi-bootstrap/observe.py --phase image --attempt 001 --output /tmp/tempest-x86-full-build-observation-001.jsonl
```

実行時の caller stdout/stderr は新 private log に保存する。以下はまだ実行していない。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-image-001 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-full-build-001/work \
  /usr/bin/env -i PATH=/usr/bin:/bin \
  HOME=/var/lib/tempest-izanagi-full-build-001/work/home \
  TMPDIR=/var/lib/tempest-izanagi-full-build-001/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-full-build-001/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-full-build-001/inputs/plugins \
  CHECKPOINT_DISABLE=1 \
  /var/lib/tempest-izanagi-full-build-001/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-full-build-001/inputs/definition/packer/tempest.pkrvars.json \
  /var/lib/tempest-izanagi-full-build-001/inputs/definition/packer/debian.pkr.hcl
```

期限・異常時の stop/kill はこの unit のみ。終了は caller exit、同 Invocation の trusted journal と service metadata、cgroup/UID/socket 回収、入力不変、guest lock-down/verify、新 image SHA を別々に照合する。GC による observer 非0を成功へ変換せず unknown と記録し、独立した証拠を照合する。失敗は原因を報告し、無断再試行・VM boot・livecall へ進まない。

snapshot はまだ未作成。全 hash と専用 user validate 結果を追記するまでは実 build の具体入力監査は未完了。

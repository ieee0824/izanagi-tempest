# Linux x86 full image build001 準備案

room #16463 に沿った準備。実 build を一度実行し、言語選択待ちで中止した。[結果と回収証拠](LINUX_X86_FULL_BUILD_001.md)を参照。以下は実行時の計画。旧 Alpine build/boot 入力と証拠は変更しない。

## 入力と snapshot

[準備記録](LINUX_X86_FULL_PREPARATION.md)と[artifact manifest](LINUX_X86_FULL_ARTIFACTS.json)の全成功を確認した後、実 `image/prepare.py --architecture x86_64` を新 private `/tmp/tempest-x86-image-definition-001` に実行する。定義内の入力は生成物の実 SHA と照合する。既存 Packer 1.15.0/plugin 1.1.8 の full validate まで確認する。

root snapshot の新 parent は `/var/lib/tempest-izanagi-full-build-001`。入力は root:tempest-kvm の directory 0750、通常 file 0440、Packer/plugin executable 0550 とする。ISO、5 artifacts、派生 definition、Packer、plugin と sidecar の全 hash/mode/owner を記録する。定義内の絶対入力 path と vars を snapshot 内へ置換し、manifest の path と template hash を更新、元 manifest SHA を別記する。置換後に専用 user の full validate を行う。

`work` とその `tmp/cache/home` は専用 uid 999 の 0700。入力 directory/file の user read 可・write 不可、source checkout clean、旧 snapshot/hash 不変、新 output 不在、専用 UID 残留なし、unit 未使用、18082/22222/5902 未使用を直前確認する。guest 用 GNU artifact の loader/GLIBC requirement の整合性を説明できない場合は実 build へ進まない。

## 観測と単発 command 案

observer は `--phase image --attempt 001` だけを新 unit に対応付ける。sample は unit cgroup の一致とその process に属する socket を検査し、Invocation の変更、非 loopback listener、GC による terminal 証拠欠落を失敗として扱う。

```sh
sudo -n /usr/bin/python3 /var/lib/tempest-izanagi-full-build-001/inputs/observe.py --phase image --attempt 001 --output /tmp/tempest-x86-full-build-observation-001.jsonl
```

実行時の caller stdout/stderr は新 private log に保存する。以下を一度実行した。

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

## snapshot と事前照合の実測

新 root snapshot を作成した。[全26 file の SHA/mode/owner](LINUX_X86_FULL_SNAPSHOT_001.json) を実 bytes と再照合した。inputs 全 directory と file は専用 uid 999 で readable/nonwritable、work/tmp/cache/home は uid 999 の private writable 0700。旧 bootstrap snapshot 001〜004 の全記載 input SHA が不変であることを先に検査した。

元定義 `inputs.json` の SHA を snapshot manifest の source_manifest_sha256 へ保存し、5 artifacts/ISO/file provisioner paths/vars を root snapshot 内へ束縛した。guest image.json は元定義から byte-identical。専用 user の env -i + snapshot Packer/plugin で full validate は exit 0。observer は collaborator の image phase 実装を snapshot へ固定した。

署名済み ISO の `/pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb` を ISO9660 records から通常 private file へ読み出し、既存 dpkg-deb -x/readelf で非実行検査した。[package/loader/libc/libm の SHA と照合結果](LINUX_X86_ISO_LIBC.json) を参照。4 artifacts の undefined GLIBC symbol/version pairs は agent145/HTTP122/LWS198/guest147 件で、全て同 package の libc/libm/loader が提供した。package の `/usr/lib64/ld-linux-x86-64.so.2` は `../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` を指す。これは ISO 内 package の予定 ABI 検査であり、guest の実 installed package/loader と実 load の受入証拠ではない。libgcc を含む共有依存全体の実 load も後続 gate に残る。

直近確認で unit は not-found/inactive、uid999 process なし、固定3 ports listener なし、free60683980800 bytes。実行直前に再確認する。snapshot 作成/full validate/ABI前段照合まで完了、この snapshot を監査後に一度実行し、中止・回収済み。

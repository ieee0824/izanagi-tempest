# bootstrap attempt004: 固定id allowlistの準備・再監査

room #16409〜11に対応する準備です。image再build・再bootは未実施です。

生成定義directory番号と実build attempt番号は別です。004を飛ばしたものではありません。
001はbind修正前の構文検査、002はbind修正後でbuild001のsnapshot元、
003はpartition修正後でbuild002、004はlock検証修正後でbuild003、
005は今回allowlist修正後でbuild004のsnapshot元です。
snapshot manifestのsource_manifest_sha256が各元定義manifestと一致することを再確認しました。
今回の対応は定義005 → snapshot/build/unit004 → log/observation004です。
過去定義を削除・番号変更・再生成していません。
[boot001](LINUX_IZANAGI_BOOT_001.md)はReady/down成功・guest UID確認不成立であり、
今回のExec拒否理由を遡って確定したとは扱いません。

## guest差分とharness診断

helperはroot所有0644の`/etc/conf.d/izanagi-agent`へ
`export IZANAGI_ALLOWED_COMMANDS=/usr/bin/id`だけを配置します。
既存regular/symlink設定は拒否し、basename idやALLOW_ALLを使いません。
後続init生成に上書きされるinit script自体には追記しません。
実guard/write blockのfixtureで既存regular/dangling設定の拒否と不変、
設定をsourceした子processへの固定絶対path exportを確認しました。
実OpenRC起動環境への到達は次のimage/bootで検証する残件です。
helper SHA256は`8242d82f83126194bc4baae3ad15dab0be146270828648a5d86639eb1e9bdf09`です。

harnessは固定`exec_status`とexit code/stdout一致/stderr有無を別に返します。
上流APIのErrはtransport/agent拒否を集約するため`exec_call_error`の未分類、他の3項目はnullです。
生error文字列による原因分類、任意stdout/stderrの出力はしません。
成功ExecOutputはmatched/nonzero_exit/unexpected_uid/unexpected_stderr、未実行はnot_attemptedです。
元の3boolによる全成功条件は緩めていません。
呼出し失敗後のdown、拒否/非0/UID違い/stderrの負例を含むRust7test・clippyが成功しました。
Python12test、sh-n、format、定義005のfull Packer validateも成功しています。

新harnessは旧binaryを保全する別targetへlocked release buildし、SHA256は
`ec135a5062690529016c87d5a835adcefda6f803c1de73e9737c23a4f297c720`です。
Cargo.lockは既報の`8e1b61a116fe967a0542fc39b75ca65e16d30c0454cc9c97582228b7b85862f9`と同じです。

```sh
cargo build --manifest-path integration/izanagi-bootstrap/Cargo.toml --release --locked --target-dir /tmp/tempest-izanagi-bootstrap-harness-target-v2
```

新harnessはまだroot配置・起動していません。

## 新snapshotと単発build案

新root `/var/lib/tempest-izanagi-bootstrap-build-004`へ003入力を複製し、helper/vars/manifestだけ更新しました。
[全13fileのhash/mode](LINUX_BOOTSTRAP_SNAPSHOT_004.json)を照合し、専用userのread可/非write、
全入力directory非write、root所有0750/0440/0550、専用work/tmp/cache0700を確認しました。
専用user full validateはexit0、001〜003入力とboot001のroot artifactはhash不変です。

監査後の直前確認はunit004未使用・UID999残留なし・固定3port空き・新output不在・13hash不変です。
observerを明示build/attempt004で先行します。

```sh
sudo -n /usr/bin/python3 integration/izanagi-bootstrap/observe.py --phase build --attempt 004 \
  --output /tmp/tempest-bootstrap-build-observation-004.jsonl
```

以下は未実行の単発案です。stdout/stderrはprivate `/tmp/tempest-bootstrap-build-004.log`へ保存します。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-build-004 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-bootstrap-build-004/work \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  TMPDIR=/var/lib/tempest-izanagi-bootstrap-build-004/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-bootstrap-build-004/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-bootstrap-build-004/inputs/plugins \
  CHECKPOINT_DISABLE=1 \
  /var/lib/tempest-izanagi-bootstrap-build-004/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-bootstrap-build-004/inputs/definition/bootstrap.pkrvars.json \
  /var/lib/tempest-izanagi-bootstrap-build-004/inputs/definition/bootstrap.pkr.hcl
```

異常時stop/killはbuild004のみ。既存証拠を保全し、再試行/fallback/bootへ進めません。
終了はclient/同Invocation最終証拠、cgroup/UID/3port回収、入力不変、lock-down/verifyと新imagehashを照合します。
GCでobserver非0ならunknownのまま記録し、trusted journal/clientを別証拠で監査します。
生成imageと新harnessのroot配置・次bootはその後の別監査です。

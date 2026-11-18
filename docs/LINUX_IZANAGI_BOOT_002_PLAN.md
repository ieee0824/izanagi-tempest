# 固定boot002: 新image・段階診断の配置と実行前監査

room #16423に従う準備です。bootは未実施です。
旧boot001のroot artifact/run/evidenceは変更せず、新root/runを分離しました。

## bindingと配置結果

| 対象 | 固定値 |
| --- | --- |
| harness IMAGE | /var/lib/tempest-izanagi-bootstrap-002/base.qcow2 |
| harness SHARE | /run/tempest-izanagi-bootstrap-002/share |
| harness SECRET | /run/tempest-izanagi-bootstrap-002/dummy.secret |
| recorder UNIT / observer | tempest-izanagi-bootstrap-boot-002.service |
| recorder OUTPUT | /run/tempest-izanagi-bootstrap-002/evidence/exit-status.json |

新root/runは不在・非symlinkを確認してからroot:tempest-kvm0750で作成しました。
[新3artifactの実bytes/hash/mode](LINUX_IZANAGI_BOOT_ARTIFACTS_002.json)はsource/installed一致、
全fileと親が専用user非write、probe実行可・image/recorder読取可でした。
probe0550、image/recorder0440、tmp/evidenceは専用user0700、空shareはroot:tempest-kvm0550です。
新独立ランダムhex dummy secretは専用user:private group0400、読取可・非writeです。
内容・hashは記録・公開していません。旧3artifactと旧exit証拠のhash不変も確認しました。

固定path変更後のlocked release buildは次のとおりです。

```sh
cargo build --manifest-path integration/izanagi-bootstrap/Cargo.toml --release --locked --target-dir /tmp/tempest-izanagi-bootstrap-harness-target-v2
```

harness SHA256は`ddb79a8211afcb8fe66ce422db64ae9480579127e0a00fa7fa8ad9ad94399824`、
lock SHA256は`8e1b61a116fe967a0542fc39b75ca65e16d30c0454cc9c97582228b7b85862f9`、
recorder SHA256は`3fb15eaec175996316857a01676d2972f9b38af6888d1bbbf16e015a915ee43b`です。
image SHA256は`7ad583f9f1514899e4f8c88b7f71609a5c0f6b76e0e213a01ef82d51f74978e5`。
依存と固定上流revは[前計画](LINUX_IZANAGI_BOOT_RUN_PLAN.md#artifactと依存)のままです。
Rust8test/clippy/format、Python12test、service静的verifyが成功しました。
002固定path、observer boot002、recorder UNIT/OUTPUT、旧Invocation拒否も対象です。
これはboot後の実UID/allowlist到達の証明ではありません。

## 単発command案（未実行）

直前に3artifact hash/mode、unit未使用、UID999残留なし、tmp/evidence/share空、secret metadataを再確認します。
先に次のobserverを開始します。

```sh
sudo -n /usr/bin/python3 integration/izanagi-bootstrap/observe.py --phase boot --attempt 002 \
  --output /tmp/tempest-izanagi-boot-observation-002.jsonl
```

監査後、以下を1回実行し、private `/tmp/tempest-izanagi-boot-002.log`へ保存する案です。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-boot-002 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=240s --property=TimeoutStopSec=5s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --property='ExecStopPost=/usr/bin/python3 /var/lib/tempest-izanagi-bootstrap-002/record_exit.py' \
  --working-directory=/run/tempest-izanagi-bootstrap-002 \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  TMPDIR=/run/tempest-izanagi-bootstrap-002/tmp \
  IZANAGI_SECRET_FILE=/run/tempest-izanagi-bootstrap-002/dummy.secret \
  /var/lib/tempest-izanagi-bootstrap-002/probe
```

受入は3bool全true/exec_status=matched/exit0、ExecOutputのexit0/stdout一致/stderrなし、
同InvocationのExecStopPost終了値、trusted最終journal、cgroup/UID/agent port/tmp残留なし、imagehash不変です。
network restrict/loopback、drive snapshot、固定share readonly引数だけを選別保存し、fw_cfg/全argvは公開しません。
GCでobserver unknownなら不在を成功へ変えず、同Invocationの別証拠として監査します。
異常時stop/killはboot002だけを対象とし、5秒後も残留なら同unit SIGKILL、再試行/fallbackはしません。
証拠と独立回収確認後に新dummy.secret固定fileだけを削除します。旧run/evidenceは削除しません。
外部到達拒否の実通信、本番VM境界、full Tempest guest/credential/live-callはこのrunの対象外・未達です。

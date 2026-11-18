# bootstrap attempt003の再監査計画

room #16389に従い準備しました。再buildは未実施です。
[attempt002失敗](LINUX_BOOTSTRAP_BUILD_002.md)への修正はhelperのlock状態検証のみです。
新rootは`/var/lib/tempest-izanagi-bootstrap-build-003`、
新unitは`tempest-izanagi-bootstrap-build-003.service`に固定します。

## 配置と検証

002のroot所有入力を複製後、helper/絶対path vars/manifestだけを変更しました。
[新13fileのhash/mode](LINUX_BOOTSTRAP_SNAPSHOT_003.json)を照合し、
root:tempest-kvm入力dir0750/file0440/executable0550、専用userのread可・write不可を確認しました。
work/tmp/cacheは専用user0700、001/002の入力hashは不変です。
専用user・空環境でのfull Packer validateは成功しました。
observerは明示`--attempt 003`に対応し、002/003のCLI→unit binding、旧cgroup拒否、
lock状態の正負fixtureを含むPython全5testとcompile、guest scriptのsh-nを検証します。

## 単発command案（未実行）

新unit未使用・UID999残留なし・固定3port空き・新output不在・13入力hashを直前確認します。
先に次のobserverを開始します。

```sh
sudo -n /usr/bin/python3 integration/izanagi-bootstrap/observe.py --attempt 003 \
  --output /tmp/tempest-bootstrap-build-observation-003.jsonl
```

監査後、以下を1回実行し、private `/tmp/tempest-bootstrap-build-003.log`へ保存する案です。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-build-003 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-bootstrap-build-003/work \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  TMPDIR=/var/lib/tempest-izanagi-bootstrap-build-003/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-bootstrap-build-003/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-bootstrap-build-003/inputs/plugins \
  CHECKPOINT_DISABLE=1 \
  /var/lib/tempest-izanagi-bootstrap-build-003/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-bootstrap-build-003/inputs/definition/bootstrap.pkrvars.json \
  /var/lib/tempest-izanagi-bootstrap-build-003/inputs/definition/bootstrap.pkr.hcl
```

異常時のstop/kill対象は003のみとし、[既存停止手順](LINUX_BOOTSTRAP_BUILD_PLAN.md#observer異常時の実行側停止手順)を適用します。
新Invocation/cgroup/両sessionを報告し、terminal・cgroup空・UID残留なし・3port閉鎖・
全snapshot入力不変・lock-down/verify・完成image hashを確認します。
001/002証拠を削除せず、観測timeoutだけで再起動しません。
probe起動/full Tempest guest/credential/live-callへは進めません。

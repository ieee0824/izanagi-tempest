# bootstrap attempt002の再監査計画

room #16377に従い準備しました。再buildは未実施です。
[attempt001失敗](LINUX_BOOTSTRAP_BUILD_001.md)の証拠は保持し、旧snapshot/途中imageは変更していません。
派生setupのみのvda2修正と失敗停止確認を追加し、元/派生setup hashを別記しています。

## 配置・検証結果

新rootは`/var/lib/tempest-izanagi-bootstrap-build-002`です。
旧rootの全13入力hashを照合してからroot所有inputsを複製し、
派生setupとsnapshot先を指すvars/manifestだけを更新しました。
[新13fileのhash/mode](LINUX_BOOTSTRAP_SNAPSHOT_002.json)を照合し、
root:tempest-kvmの入力dir0750/file0440/executable0550、専用userのread可・write不可を確認しました。
work/tmp/cacheはtempest-kvm所有0700。旧13入力hashは配置後も不変です。
専用userの空環境・新snapshot固定pluginによるfull Packer validateはexit0でした。
完成image/guest内での修正成功は未検証です。

## attemptを混ぜない起動・観測案

observerは`--attempt 002`を追加し、選択肢を001/002に限定しました。
unit/cgroup照合、Invocation変更拒否、listen確認の条件は同じです。
2testとPython compileに成功しました。

```sh
sudo -n /usr/bin/python3 integration/izanagi-bootstrap/observe.py --attempt 002 \
  --output /tmp/tempest-bootstrap-build-observation-002.jsonl
```

observer起動後、監査を経て次の固定commandを単発で行う案です。
新unit未使用・旧unit terminal・UID999残留なし・3port空・新output未存在・全入力hash不変を直前確認します。
stdout/stderrはprivate `/tmp/tempest-bootstrap-build-002.log`へ保存します。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-build-002 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-bootstrap-build-002/work \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  TMPDIR=/var/lib/tempest-izanagi-bootstrap-build-002/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-bootstrap-build-002/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-bootstrap-build-002/inputs/plugins \
  CHECKPOINT_DISABLE=1 \
  /var/lib/tempest-izanagi-bootstrap-build-002/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-bootstrap-build-002/inputs/definition/bootstrap.pkrvars.json \
  /var/lib/tempest-izanagi-bootstrap-build-002/inputs/definition/bootstrap.pkr.hcl
```

異常時は[停止手順](LINUX_BOOTSTRAP_BUILD_PLAN.md#observer異常時の実行側停止手順)の
unitを**002**へ固定してstop/killします。001へ停止操作を向けません。
新InvocationID/ControlGroupと両sessionを報告し、terminal・cgroup空・UID残留なし・3port閉鎖・
入力hash不変、lock-down/verifyと完成image hashを独立に照合します。
観測timeoutだけで再起動せず、失敗時は新証拠を保持して停止します。
probe起動、full Tempest guest、credential/live-callはこのbuildには含みません。

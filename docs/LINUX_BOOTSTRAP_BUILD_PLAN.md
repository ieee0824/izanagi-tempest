# 専用userによる最小bootstrap image build計画

本書はroom #16358の起動前監査資料です。image buildは未実施です。
[入力・署名根拠](LINUX_IZANAGI_BOOT_PLAN.md)と[生成手順](../integration/izanagi-bootstrap/README.md)を前提にします。

## 入力snapshotと書込み先

予定rootは`/var/lib/tempest-izanagi-bootstrap-build`、既存path/symlinkがあれば停止します。
rootと`inputs`はroot:tempest-kvm 0750、ISO/agent/template/vars/helper/http入力は0440、
Packer/plugin executableは0550に固定し、専用userが書換えできないことを確認します。
ISO、agent、Packer、pluginのhashは既記録値と照合します。
生成器はroot所有snapshotのISO/agent絶対pathを引数に使い、`inputs/definition`へ出力します。
上流sourceは変更せず、manifestに元template/ISO pinと署名確認後override、全生成hashを保存します。

専用user所有0700の`work`、`work/tmp`、`work/cache`だけを作成します。
出力image、Packer log、plugin一時socket等はこの範囲へ置きます。
host通常HOME、認証済みCLI、実credential、実AWSは入力に含みません。
build中はAlpine package取得用egressを使うため、実験runのnetwork拒否とは区別します。
build用root guest認証は上流lock-down/verify-imageで除去し、成功manifestと完成image hashを保存します。

## 一時listen範囲

QEMU plugin 1.1.8 source commit `ad7af6f6b764d5adf42cd3cd578c868b80f6bd87`を参照しました。
`step_run.go`の既定SSH hostfwdはhost address省略なので、派生定義で明示overrideします。
HTTP/VNC/SSH forwardは127.0.0.1、portは18081/5901/22221に固定します。
実行前に全portが未使用であることを確認し、使用中なら別portへ自動変更せず停止します。

`step_http_ip_discover.go`はspecific http_bind_addressをHTTPIPに採用するため、
HTTPを127.0.0.1にbindしたままboot commandのHTTPIPを使うとguest自身を指します。
派生boot commandはslirp host alias `10.0.2.2`へ固定します。
QEMUの`-netdev user,id=user.0,hostfwd=tcp:127.0.0.1:...-:22`も明示します。
これはsource/定義の確認であり、実際のguest到達性やlisten範囲はbuild中の`ss`とprocess/cgroupで確認します。
wildcard/external listenを検出した場合は対象unitを止め、診断を保存して監査します。

## 固定build command案（未実行）

snapshot配置と再hash照合が完了した後、以下を管理者が単発transient unitとして実行する案です。
未使用unit名、専用identity、device0660維持、入力非書換え、出力directory未存在を実行直前に確認します。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-build-001 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=3600s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --working-directory=/var/lib/tempest-izanagi-bootstrap-build/work \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  TMPDIR=/var/lib/tempest-izanagi-bootstrap-build/work/tmp \
  PACKER_CACHE_DIR=/var/lib/tempest-izanagi-bootstrap-build/work/cache \
  PACKER_PLUGIN_PATH=/var/lib/tempest-izanagi-bootstrap-build/inputs/plugins \
  CHECKPOINT_DISABLE=1 \
  /var/lib/tempest-izanagi-bootstrap-build/inputs/packer build -color=false -on-error=abort \
  -var-file=/var/lib/tempest-izanagi-bootstrap-build/inputs/definition/bootstrap.pkrvars.json \
  /var/lib/tempest-izanagi-bootstrap-build/inputs/definition/bootstrap.pkr.hcl
```

`-on-error=abort`で再試行やdebug待機へ進めません。3600秒は全buildの外側上限です。
`--collect`は使わず、別の観測processでInvocationID/ControlGroupとlisten状態を実行中から保存します。
成功判定はPacker exit0だけでなく、lock-down/verify成功、完成image hash、unit terminal、
cgroup空、UID999残留なし、固定port閉鎖を照合します。期限/失敗時は同unitのcontrol-group回収後に確認し、
作成途中imageは成功入力にしません。部分成果物は診断保全後に対象を限定して扱います。
root QEMU/TCGや別architectureへのfallback、無断再実行はしません。

完成imageは別のroot所有固定配置へ移し、同じhashを確認してから
[最小boot harness](../integration/izanagi-bootstrap/README.md)の単発起動を別に監査します。
このbootstrap imageはfull Tempest guest/派生Debianや正式VM境界受入の代替ではありません。

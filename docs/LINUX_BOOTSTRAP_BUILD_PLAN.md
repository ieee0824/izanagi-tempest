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

snapshot作成時の対応は次のとおりです。まだ配置していません。

| 照合済み取得物 | snapshot内の配置先（root配下） | mode |
| --- | --- | --- |
| Packer1.15.0 binary | inputs/packer | 0550 |
| plugin1.1.8 binaryと登録checksum | inputs/plugins/github.com/hashicorp/qemu/配下の同名file | binary0550/checksum0440 |
| Alpine3.23.3 ISO | inputs/base.iso | 0440 |
| x86_64 musl agent | inputs/izanagi-agent | 0440 |
| 派生template/helper/http/lock-down/verify | inputs/definition/配下 | 0440 |

各directoryをroot:tempest-kvm0750で作成し、全fileのinstall後hashを元の記録へ再照合します。
vars内のISO/agent絶対pathをsnapshot先へ固定し、変換前後vars hashをmanifestへ記録します。
`http_directory=${path.root}/http`により、書込み可能なworkをcwdにしてもHTTP入力はroot所有snapshotです。
snapshot後の`inputs`全fileのSHA256一覧、`namei -l`、専用userのread/execute可と非writeを確認します。
manifest自身もroot所有0440とし、hash一覧の自己参照は含めません。
snapshotのvarsで再度Packer validateを行い、既存source/private pathへの依存が残っていないか確認します。
buildを開始する前にこの配置結果をルームへ提示します。

### 2026-11-18の配置実測

room #16365の監査指示後、上記配置を実施しました。
[全13fileのinstalled hash/mode一覧](LINUX_BOOTSTRAP_SNAPSHOT.json)は元入力のhashと一致しました。
全input fileを専用userがread可・write不可、全input directoryがwrite不可と確認しました。
rootからdefinitionまでroot:tempest-kvm0750、template等0440、実行file0550です。
work/tmp/cacheはtempest-kvm:tempest-kvm0700です。
varsのISO/agentはsnapshot絶対pathへ変更し、元/新vars hashをroot所有manifestへ記録しました。
専用userの空環境・固定Packer/pluginによるfull validateはexit0でした。
固定3portはlistenなし、ubuntu非kvm、専用groups988+993、device root:kvm0660を再確認しました。
Packer buildはまだ実行していません。

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

## observer異常時の実行側停止手順

observerは読取専用なので、異常終了だけではbuildは止まりません。
build実行側はobserverのprocess/sessionとbuildのprocess/sessionを別に保持し、
observerの非0、非loopback検出、Invocation変更、観測不能を確認したら直ちに固定unitへ次を実行します。

```sh
sudo -n /usr/bin/systemctl stop --no-block tempest-izanagi-bootstrap-build-001.service
sudo -n /usr/bin/systemctl show tempest-izanagi-bootstrap-build-001.service \
  -p InvocationID -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus -p ControlGroup
```

停止を発行しただけで回収完了とはしません。記録済みInvocationIDとcgroupに対し、
TimeoutStopSec=10sを越えてもtaskが残る場合は、同unitを対象に次を発行します。

```sh
sudo -n /usr/bin/systemctl kill --kill-whom=all --signal=SIGKILL tempest-izanagi-bootstrap-build-001.service
```

その後もunit terminal、cgroup空、UID999残留なし、固定port閉鎖を確認し、
達成できなければ回収未確認の失敗として報告します。observerの単なるtimeoutは新build開始理由にしません。
`systemd-run --wait`の実clientは終了直前までunit参照を保持するため、
別観測側で終了属性をclient終了前に保存します。保存できなければ証拠不足として成功にしません。
観測記録・build log・途中imageは保持し、診断前にreset-failedやdirectory削除を行いません。

完成imageは別のroot所有固定配置へ移し、同じhashを確認してから
[最小boot harness](../integration/izanagi-bootstrap/README.md)の単発起動を別に監査します。
このbootstrap imageはfull Tempest guest/派生Debianや正式VM境界受入の代替ではありません。

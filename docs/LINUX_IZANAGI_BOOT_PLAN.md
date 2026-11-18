# 固定Izanagi最小起動の棚卸しと計画

2026-11-18、room #16330に従うread-only調査です。起動・build・package installは未実施です。
固定dummy KVM成功は[実測](LINUX_KVM_ARTIFACT.md)の範囲に限定します。

## 専用hostの現状

`/home/ubuntu`直下は本repositoryのみ、`/opt`と`/srv`にIzanagi配置はありません。
PATH上の`izanagi`、`qemu-system-x86_64`、`qemu-img`、`packer`は不在です。
これは当該pathの確認であり、全filesystemにartifactがないという主張ではありません。
既存x86_64 agent/sidecar/imageの受入可能なmanifestはまだ確認できていません。

上流sourceを`/tmp/tempest-izanagi-upstream-review`に取得し、既存手順の固定commit
`16d0b55947006a166cfa29dcb8bfe71f65f8c36a`へdetached checkout、cleanを確認しました。
Cargo.lock SHA256は`9085ec0bc69678c4c060e82dd8dfa7ce32dd932dd6406c3a4f4a081e28aeae6b`です。

## 上流の候補と差分

`packer/alpine-x86_64.pkr.hcl`はKVM、Alpine 3.23.3 x86_64、musl agent用です。
定義SHA256は`77c17773d03badbcce8b95e94222b2d750b730ffc8a1aa5746307e17c5d6f531`。
ISO候補は`https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-virt-3.23.3-x86_64.iso`、
上流固定SHA256は`366285bfa4d25429e0a9d1c5cbe3c2e35e84e1ad5e0620e8b5a20b5e39e7e02b`です。
ISO自体は未取得・未照合、完成qcow2 hashは未確定です。これは派生Debianの代替ではありません。

hostの`src/qemu_sandbox.rs`はx86_64でqemu-system-x86_64、KVM、q35、cpu hostを選びます。
image defaultはaarch64名なので、固定x86_64 imageの絶対pathを明示する必要があります。
`restrict_network=true`はuser networkのrestrict=onとagent転送のloopback bindへ対応します。
snapshot=onでも9p共有への書込みは保護しないため、空の専用共有をread-onlyに限定します。

上流Alpine setupは9p moduleを追加しますが、qemu_fw_cfg moduleの明示追加はありません。
agentはfw_cfg token不在を拒否するため、kernel config/module/autoloadを先に確認し、
必要なら固定派生定義へmodule設定を加えます。認証を無効にして回避しません。
既存`qemu_protocol_smoke`はExecに加えてtrace Eventを要求します。
non-ebpf agentでの最小boot成立とは別条件なので、そのまま最小boot判定に使いません。

さらにAlpine setupはuser作成に`no`を渡し、x86 templateも`izanagi` userを作成しません。
agentのExecは`EXEC_USER=izanagi`を要求し、不在ならroot実行を拒否します。
従ってReadyだけでなく固定Execも確認する最小派生では、guestの専用非特権user作成を
明示的な差分として定義・検証する必要があります。

## ツール固定候補（未導入）

現在のローカルAPT indexにある候補は以下です。package本体・依存closureは未取得です。

| package | version | index記載SHA256 |
| --- | --- | --- |
| qemu-system-x86 | 1:8.2.2+ds-0ubuntu1.18 | 14602e262627adac030329d2cecfee5f6c0938b34566ff2ea2d4c9a9eb02430d |
| qemu-utils | 1:8.2.2+ds-0ubuntu1.18 | 10695e57937d8a1d0ec6d017a6770d02353ec0c9500e4a36928230b2d39026c5 |

PackerはAPT候補なし。公式`https://releases.hashicorp.com/packer/1.15.0/packer_1.15.0_SHA256SUMS`
を取得し、`packer_1.15.0_linux_amd64.zip`の記載hash
`2fd1149c5c6c7604ced64d7b56638af05f6b7ed3f6835182bc913ddaba1f16b8`を確認しました。
本体は未取得で、plugin versionとchecksumもまだ未確定です。
agent固有Cargo.lock SHA256は`9db17aed3c43477d9bc16dfe65b453b6dc0bb36d4f8e8fc8e7b9814edf200bc6`。
hostのinstalled Rust targetはx86_64-unknown-linux-gnuのみで、musl toolchain準備も必要です。

## 起動前に具体化する手順

1. QEMU/Packer/pluginの固定versionと入手元、host/agent build commandとlockを提示する。
   hostは固定sourceのnative release、agentは同commitのx86_64 muslを候補とし、生成hashを記録する。
2. 既存の完成base imageを利用できるか確認する。ない場合は、最小base構築をfull guest/派生Debian再構築と区別して監査する。
   ISO、template、provision/lock-down/verify script、agent、完成imageのhashを固定する。
3. 認証Ready→固定dummy Exec→downだけを行う最小harnessをレビューし、引数・config・環境を固定する。
   protocol secretは実credentialと独立したdummy値とし、private fileで受け渡す。
4. root所有の非書換えbinary/image/configと、専用userのみ書込み可能なrun領域を分ける。
   固定commandはartifact hashと配置先の確定後に提示する。現在は実行可能な最終command未確定。
5. 外側deadlineの対象をQEMU childまで含む監視単位にし、正常/失敗/期限時にkill・waitと
   残留process、listen port、token/secret file、snapshotの回収を確認する。
   上流downは10秒後killへ進みますが、Dropはtokenのzeroizeのみなので、親強制終了での回収を仮定しません。
6. 起動時はnetwork制限、外部到達拒否とloopback agent経路を実測する。
   成功後もowner/firewall/doas/mailbox/control/clock/timeout等の本番VM境界は未検証として残す。

これらのartifactと具体commandの監査後に単発起動へ進みます。
fresh login、subscription live-call、full guest/派生Debian再構築は本調査では行いません。

## systemdによる起動・回収案（未実行）

hostでは`/usr/bin/systemd-run`、systemd 255 (255.4-1ubuntu8.18)、
system manager state `running`、cgroup v2をread-onlyで確認しました。
room #16336に従い、新たな汎用root launcherではなくtransient serviceを候補にします。
実行対象は監査済み固定harnessのみとし、次のpropertyを固定します。

```ini
User=tempest-kvm
Group=tempest-kvm
SupplementaryGroups=kvm
Type=exec
KillMode=control-group
RuntimeMaxSec=240s
TimeoutStopSec=5s
SendSIGKILL=yes
Restart=no
UMask=0077
```

240秒はboot/retry全体の外側上限であり、上流の全retry完遂を保証しません。
上限に達したrunは失敗として停止し、再実行やfallbackを行いません。
固定harnessは`env -i`から固定PATHとprivate run領域のみを受け取り、
通常HOME、Claude設定、実credential、既存MCP設定を渡しません。
QEMUはsystem serviceの同じcgroupを継承し、通常userへkvm権限を与えません。

実施時は未使用の固定unit名を確認し、起動前後のunit状態とcgroupを保存します。
`--collect`で証拠を即時に捨てず、Result、ExecMainCode、ExecMainStatus、
ActiveState、SubState、ControlGroup、InvocationIDを読み取ります。
正常main終了だけを成功にせず、harnessのReady/固定Exec/down各診断と、
cgroup配下の残留taskなし、UID999の残留processなし、agent port閉鎖、
private token/secret fileなしを独立に照合します。
cgroupが既に削除された場合はunitのterminal状態と当該InvocationIDを照合し、
不在だけを正常終了の証明にはしません。
失敗unitのresetやrun領域削除は診断保存後に対象を限定して行います。

systemdの設定案を実行済みの回収証拠とは扱いません。
harnessと固定path/hashの確定、transient unit設定の検証が起動前の残件です。

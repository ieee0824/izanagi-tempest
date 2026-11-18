# 固定Izanagi最小boot001の配置・実行前監査

room #16401でbuild003のimage生成・最終化・独立回収と終了証拠の組合せが受け入れられました。
再buildは不要とし、以下は最小bootの準備です。
room #16404後に単発起動し、Ready成功・guest UID確認不成立となりました。
[実測と回収](LINUX_IZANAGI_BOOT_001.md)を参照してください。以下は当時の計画です。

## artifactと依存

新配置先`/var/lib/tempest-izanagi-bootstrap`の不在・非symlinkを確認し、root:tempest-kvm0750で作成しました。
[全3artifactのinstalled SHA256/mode](LINUX_IZANAGI_BOOT_ARTIFACTS.json)をsourceと再照合しました。
probe0550、base.qcow2/record_exit.py0440、全fileと親を専用user非writeと確認しました。
probeは専用user実行可、image/scriptはread可です。先祖`/`、`/var`、`/var/lib`はroot:root0755です。

harness SHA256は`68b40e7382906fcab237409513c6dae2ce014f763371f1a068ae7bf3fea07c92`、
独自Cargo.lock SHA256は`8e1b61a116fe967a0542fc39b75ca65e16d30c0454cc9c97582228b7b85862f9`です。
上流git revは`16d0b55947006a166cfa29dcb8bfe71f65f8c36a`、default features、build commandは次のとおりです。

```sh
cargo build --manifest-path integration/izanagi-bootstrap/Cargo.toml --release --locked --target-dir /tmp/tempest-izanagi-bootstrap-harness-target
```

NEEDEDはlibgcc_s/libm/libc/loader、RPATH/RUNPATHなし、空環境loader --listで解決を確認しました。
この操作ではharness entryを起動していません。libraryのroot所有依存は[既存監査](LINUX_KVM_DEPENDENCIES.md)と対応します。
record_exit.pyはPython標準libraryのみを使い、`/usr/bin/systemctl`を読取実行します。
Pythonは3.12.3、実体`/usr/bin/python3.12`、binary SHA256は
`e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`、
systemctl SHA256は`37ec607113f55f1b385b4fa75588a43402aec0de57927500763b267713f10f63`です。
全Python runtime依存closureの網羅を主張するものではありません。
imageはqcow2、virtual2GiB、backing fileなし、corrupt/dirty=falseをread-onlyで確認しました。

## private runとdummy secret

新`/run/tempest-izanagi-bootstrap`も不在・非symlinkを確認し、root:tempest-kvm0750としました。
tmp/evidenceのみtempest-kvm所有0700、空shareはroot:tempest-kvm0550です。
親を専用user非writeとしてshareとsecretのpath置換を防ぎ、一時fileはtmpへ限定します。
独立ランダムhexのdummy secretを専用user:private group0400で新規作成し、read可・write不可を確認しました。
内容・hashは出力・公開していません。既存credentialやClaude設定は使いません。
上流loaderのUTF-8非空trim/mode0400または0600条件に合わせています。

## 単発command案（未実行）

固定unit未使用、UID999残留なし、private tmp/evidence/share空、全artifact hash不変を直前確認します。
observerは`--phase boot --attempt 001`でbuild unitと区別します。

```sh
sudo -n /usr/bin/python3 integration/izanagi-bootstrap/observe.py --phase boot --attempt 001 \
  --output /tmp/tempest-izanagi-boot-observation-001.jsonl
```

observer開始後、監査を経て以下を1回実行し、private logへ保存する案です。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-bootstrap-boot-001 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=240s --property=TimeoutStopSec=5s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --property='ExecStopPost=/usr/bin/python3 /var/lib/tempest-izanagi-bootstrap/record_exit.py' \
  --working-directory=/run/tempest-izanagi-bootstrap \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  TMPDIR=/run/tempest-izanagi-bootstrap/tmp \
  IZANAGI_SECRET_FILE=/run/tempest-izanagi-bootstrap/dummy.secret \
  /var/lib/tempest-izanagi-bootstrap/probe
```

受入はharnessのready/guest_uid_matched/down_returned_ok全trueとexit0、
ExecStopPostの同Invocation/main終了値、trusted journalの最終deactivation、
cgroup空・UID残留なし・agent port閉鎖・tmp内token/secret/snapshot残留なし・image hash不変です。
ExecStopPost snapshotはdeactivating時点になり得るため最終terminalとは区別します。
observerがGCでunknown/非0になった場合も勝手に成功へ変えず、保存snapshot/journalを別に監査します。
観測間の短時間listen網羅性は主張せず、QEMU restrict=on/loopback hostfwd/snapshot/read-only shareの実引数を照合します。
外部到達拒否の実通信試験、本番owner/firewall/doas/mailbox等は後続gateです。

非loopback/観測不能/別Invocation/失敗なら固定boot001だけへstop --no-block、
5秒後も残留なら同unit kill --kill-whom=all --signal=SIGKILLとし、再実行・fallbackは行いません。
終了後はexit evidence/logを保全し、独立回収確認後に固定dummy.secretだけを削除して非存在を確認します。
run領域全体や過去build証拠を無条件削除しません。full Tempest guest/credential/live-callへは進めません。

boot bindingを含むPython全10testとservice静的verifyは成功しています。
実unitのExecStopPost収集、boot後UIDや回収は未検証です。

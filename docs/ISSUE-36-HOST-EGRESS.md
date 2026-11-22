# #36 ホスト vsock 中継の実装状況

## 範囲

承認済み[B案](ISSUE-36-EGRESS-B-DRAFT.md)のホスト側を実装している。
guest gatewayの新transportとready検証を接続し、NICなしVMでdummy経路を受入した。
owner VMへの実配備と最終配置チェックは未完了。
Claude loginや実認証先への試験接続は行わない。

## 原本と起動境界

`tools/host_ledger/egress_daemon.py`はroot専用の起動口である。
既存control brokerとは別プロセスとして同時起動しない。同じprocessでCID2の
23100/control（8worker、同CID1要求）と23105/data（4worker）をbindする。
片方のportが使用中なら起動を拒否する。signal終了では不可逆stopを先に公開する。

`/var/lib/izanagi-tempest`以下に既存のhost台帳/checkpoint、channel登録/承認、
署名鍵と、guestへ公開するものと同じ`claude-login-authority`、
`claude-login-publication`のホスト原本を保持する。directoryはroot:root0700、
fileはroot:root0600/単一linkであり、symlinkを受理しない。
公開の`lock`を共有取得して`pending`、`revocation-pending`、floor、currentを確認し、
既存manifest5入力、独立approved-generation、handoff署名、独立trust key、
version2 policy、fixture-v1 revocation署名と独立確定記録を検証する。
relay中にpublication/SQLiteのlockを保持しない。

さらに`host-login-authority`に次のホスト原本を必要とする。

- `egress-trust-key`: 独立配備したEd25519公開鍵32 bytes。
- `egress-policy.json`: 専用domain `izanagi-tempest:login-egress-policy:v1\0` と
  canonical JSONを署名した`payload`/`signature` envelope、4096 bytes以下。
  payloadはversion1、scope、boot_id、manifest_sha256、approved_ips_revision、
  authority、peer/address/port、expires_unix_msに厳密限定する。
  authorityは`platform.claude.com:443`、portは443。数値addressは既存公開世代の
  承認IPに含まれる必要がある。期限はchannel独立承認と既存世代の最早期限以下。

起動時のscope/manifest/route/信頼鍵/登録は固定する。原本を250ms間隔で再検証し、
QMP peer、QEMU lifetime/CID、台帳/checkpoint、世代変更、失効、期限、sequence rollbackを
検査する。更新失敗は同一実行を不可逆stopにする。監視処理はcontrol leaseを更新しない。
control署名応答を正常送信した後だけ、host受理時の単調時計を起点に最長2秒更新する。

## guestの鍵とtransport

guestのready検証は、既存root原本`/etc/tempest/host-channel-key`を使う。
これはhostの`host-login-signer/signing-seed`に対応するcontrol信頼鍵であり、
ホストのegress-policy検証用`egress-trust-key`とは別である。配備時に双方の対応を確認する。
署名domainもreadyとcontrolでは異なるため、control receiptをreadyへ流用できない。

distribution入口は既存のhost-channel登録、公開manifest、承認peerを固定して新経路へ進む。
AF_VSOCKは専用OwnedFd型で保持し、getpeernameのsockaddr_vmでCID2/port23105を照合する。
CONNECT検査後にchallengeを生成し、2秒以内の署名readyを検証してから200を返す。
relayはparentの共有stopを各I/O直前に確認する。テスト専用FixedDummyの既存TCP対照は維持する。

## ローカル検証

Python 3.11以降と`image/requirements.txt`の依存を使う。

```bash
python3 -m unittest discover -s tests -p 'test_egress*.py' -v
python3 -m unittest discover -s tests -p test_host_ledger_channel.py -v
sudo python3 -m unittest discover -s tests -p test_egress_generation.py -v
```

最後のコマンドは`/run`内の一時dummy原本だけでroot metadataを検証し、終了時に削除する。
通常実行ではその1件をskipする。試験はloopback/socketpairのみで、実credentialは使わない。
署名/独立承認/世代/失効の拒否、readyのchallenge/実peer/期限、binary双方向転送、
失効/片方向EOF/backpressure時の両端閉鎖、data4枠飽和時のcontrol独立性を確認する。
root metadata試験はpending marker、非private mode、symlinkの拒否も確認する。

配備原本が受入済みになった後の起動口は以下である。現時点では運用開始済みとは扱わない。

```bash
sudo python3 tools/host_ledger/egress_daemon.py
```

起動自体はpermitを発行/consumeしない。未配備/失効済み/未承認原本では拒否する。
TLSの終端/復号やpayload記録は行わず、ready後は方向ごと64KiB以下の不透明中継だけを行う。

## NICなしVMでの実測

2026-11-22、fixture `9385293`、Rust libtest source `5f3c960`で終了code0。
専用non-login `tempest-kvm`ユーザーのKVM、kernel `6.8.0-149-generic`、NICなし、
curated readonly9pで実施した。上流はhost `127.0.0.1:443`のdummy TLSだけである。

- production `load_run` / `HostOriginals` / `serve_both`とguest `Route`の実AF_VSOCKを接続した。
  専用ready署名、CONNECT200、UID999のTLS証明書/名前検証、PING/PONGを確認。
- 拒否CONNECTの直後に上流TCP accept=0をassertし、その確認後だけ正常TLSへ進む。
  正常後はTCP accept=1、TLS accept=1。TLS handshake成功だけをdialなしの根拠にはしない。
- revokedは209ms、response-lostは211msで両TLS端close。
  各run consume=1/query=2の更新成功後に停止を発生させ、TLS close=1を確認した。
- 同じVMで実`isolated_command`を通るmanual childがUID999/AF_VSOCK EPERM、
  namespace_reaped=trueを確認。TLS probe自体を実Claude CLIと同一視しない。
- gateway正常終了、host worker join、VM poweroff、readonly exportの削除を確認。
  終了後hostの23100/23102/23105 listenerとdummy443 listenerは残っていなかった。

logは`/var/tmp/tempest-egress-vm-final.log`、SHA256
`c723f46c436d834c0336eeb3a34da57cf07390554abe821e056fba41a9443553`。
libtest SHA256は`5e439b35ed63b249acb981a7a77e20d00b1988bcd010988686960f72dd3e0fd9`。
前の試行ではfixtureのPython制御clientの鍵型/壁時計検証、および空行のreadiness判定で停止した。
最終試行は本番と同じRust control clientのrequest-start単調時計検証を使い、
全readを期限付きにした。productionの認可条件は緩めていない。

この環境での再現コマンドは以下。release各binaryとlibtestを準備し、未使用のexport名を使う。

```bash
CARGO_TARGET_DIR=/var/tmp/tempest-fixed-dependency-bundle/target cargo test --locked --offline --release -p tempest-linux-probe --lib --no-run
sudo unshare --mount --propagation private python3 integration/prepare_login_vm_runtime.py \
  --output /var/lib/tempest-egress-runtime-final \
  --binary-directory /var/tmp/tempest-fixed-dependency-bundle/target/release \
  --libtest /var/tmp/tempest-fixed-dependency-bundle/target/release/build/tempest-linux-probe/f7ee4b13e2926d7f/out/tempest_linux_probe-f7ee4b13e2926d7f \
  --command python3 integration/qemu_login_runtime.py \
  --kernel /boot/vmlinuz-6.8.0-149-generic --kernel-release 6.8.0-149-generic \
  --runtime /var/lib/tempest-egress-runtime-final --egress-fixture
```

libtestのhash付きpathはtoolchainで変わるため、最初のcommandの出力を使う。
実VMでの全data slot占有は行っていない。5本目data拒否とcontrol独立性は既存ローカル試験の範囲。
新経路のactual distribution入口による本人login、実credential、実認証先への接続は未実施。

## 残る配置チェック

マージ済み成果物のentry/host relay、root原本と独立鍵、owner VMのQEMU lifetime/CIDを
再照合して配備する。固定CLIや全世代の監督・回収契約は既存入口のものを維持する。
新経路のdummy transport試験を、実Claude loginや全manual supervisorの再受入へ拡張しては扱わない。
ホスト原本の生成・公開・配備手順も最終成果物と照合する。本人login担当はownerのままである。

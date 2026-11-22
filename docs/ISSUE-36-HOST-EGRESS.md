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

## 操作期限と更新される鮮度

本人の操作hard capは300秒。通信承認、permit、handoff、公開世代の最早期限でさらにcapし、
初回revocationの30秒期限を操作全体の期限へ混ぜない。control leaseは最長2秒のまま。
revocation署名の各状態は最長30秒で、親だけがより大きなrevisionを検証して共有leaseを更新する。
同revisionの再読で単調時計期限を延長せず、旧期限を越えた後の新署名でも復活しない。

`refresh_revocation.py`はhostで署名し、host/guestそれぞれのroot原本へ公開する共通処理を提供する。
秘密鍵はhostだけに保持し、guestへ配送するのは署名済みbytesのみ。操作期限は最初に単調時計へ
固定し、updaterも期限で停止する。配送の上限は旧鮮度/操作期限/10秒の最早値である。
これは管理側の原本配送であり、control/data handshakeの2秒期限を変更しない。

正常refreshは新しいstate/signature/commit/floorをstageしてからpublication EX lockで切り替える。
runtime readerがSHを取れない間は既存の未失効leaseだけを参照し、延長はしない。
pending marker、署名不正、rollback、期限切れは引き続き不可逆stop。
初回preflightはbusyでも拒否する。部分更新や配送失敗では不確定markerを残して隔離する。

この分離とpublisherはローカル試験とNICなしVMで受入済み。実VMではvsockの試験carrierで
署名状態を配送し、本番と同じguest固定root入口へ渡した。本番SSH carrierの対象VM実測は
再配置時に行う。下の053cab8系の初回証拠と、後述の操作期限分離後の証拠を区別する。

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
sudo python3 -m unittest discover -s tests -p test_egress_refresh.py -v
```

最後のコマンドは`/run`内の一時dummy原本だけでroot metadataを検証し、終了時に削除する。
通常実行ではgenerationの1件とpublisherの3件のroot試験をskipする。試験はloopback/socketpairのみで、実credentialは使わない。
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

## 操作期限分離後の実VM受入（2026-11-22）

source `8041852`、Rust libtest source `407769d`、session26352終了code0。
専用non-login KVM user、kernel6.8.0-149、NICなし、readonly9p、host loopback dummy TLS。
試験専用VMの壁時計だけをhostへ合わせた。owner VMの時刻は変更していない。

- 本番と同じguest `--publish-stdin`入口でboot、署名、scope、revision、digest ACKを検証した。
  初回source公開と定期状態の配送には試験vsock RPCを用い、秘密seedはhostに残した。
  native `ScopedLoginRevocation`の親更新と共有leaseも実経路へ接続した。
- freshness-lost: 設定operation cap90秒で、35秒時点までTLS生存、署名配送4回、control query165回。
  更新を止めた後24851msで両TLS端を閉鎖。queryは280回まで継続しており、
  control更新の停止ではなく最後のsigned freshnessの終了で回収した。operation期限90秒より早い。
- operation-deadline: **試験用のoperation期限は50秒**。35秒時点まで生存・配送4回。
  その後も更新を続けたが、設定期限に到達して閉鎖した（35秒確認後13976ms、最終配送5回/query229回）。
  本番上限300秒の端点はローカル境界試験とvalidatorの静的確認による。300秒待つ実VM試験とは扱わない。
- revoked149ms、response-lost200msでも両TLS端close。各run consume1、正常TCP/TLS accept1、TLS close1。
  拒否CONNECTの直後は上流TCP accept0をassertした。
- 同じVMで実manual-childのUID999/AF_VSOCK EPERM/namespace_reapedを確認。
  gateway正常終了、host worker/updater join、VM poweroff、export削除、待受け不在を確認した。

log `/var/tmp/tempest-operation-vm-8041852.log` SHA256:
`4ac7c1464356b84aea12a4004d432c4e9d4ba05fa3640c177679b65b8998efae`。
libtest SHA256: `a093afbcf9387769519b857270b0ef72a0f53fe7398f187368264d7aaf05a698`。

全Python243件中239成功/root4skip、root publisher9件成功。
workspace cargo test、workspace build、fixture featureを含む全target clippy、fmtが成功。
再現は前節と同じ`--egress-fixture`コマンドを用い、sourceとlibtestを今回のものへ置き換える。

## 本番の失効状態配送

hostは`refresh_revocation.py --run-login-vm-updater`をrootで実行する。
独立した`host-login-signer/revocation-seed`を使い、対応public keyとの一致を確認する。
ownerが保持を指示した管理SSH鍵を、署名済み公開状態の固定配送に限って使用する。
秘密署名鍵、CLI credential、TLS payloadはguestへの配送・ログ出力へ含めない。

SSHは固定先`tempest@127.0.0.1:22333`、固定管理鍵とknown_hosts、agentなし、転送なし。
remote commandは固定`sudo -n /usr/bin/python3 -B /usr/local/lib/tempest-login-host-ledger/refresh_revocation.py --publish-stdin`。
受信側のsourceは固定`/etc/tempest`。stdinからpathやscopeを選択させず、root登録と実bootを照合する。
受信済みの同一bytesの再送はファイルを再公開せず同じACKを返し、leaseも延長しない。

## 残る配置チェック

マージ済み成果物のentry/host relay/publisher、root原本と独立鍵、owner VMのQEMU lifetime/CIDを
再照合して配備する。固定CLIや全世代の監督・回収契約は既存入口のものを維持する。

- 本番SSH carrierでdummy署名状態を1回配送し、正確なACKまで対象VMで確認する。
  実permitの発行/消費、実認証先への接続は行わず、dummy sourceは確認後に回収する。
- 本番管理設定で操作上限300秒を静的に照合する。初回30秒freshnessを操作期限へ混ぜない。
- 本人の開始合図より前に、期限付きの通信/単回許可原本を発行しない。
  開始直前に実承認2件の確定bytesからapproval_pair digestを計算しhandoffへ固定する。

新経路のdummy transport試験を、実Claude loginや全manual supervisorの再受入へ拡張しては扱わない。
本人への案内には起動command、発行後の実際の残秒（最大5分）、開始合図、停止方法を含める。
本人login担当はownerのままである。

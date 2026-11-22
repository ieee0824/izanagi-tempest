# #36 ホスト vsock 中継の実装状況

## 範囲

承認済み[B案](ISSUE-36-EGRESS-B-DRAFT.md)のホスト側を実装している。
guest gatewayの新transportとready検証まで接続した。実VMでの新経路の受入、実配備は未完了。
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

## 残る受入

dummy TLSの実vsock中継、実manual childの
迂回拒否との両立、失効/更新停止/QEMU停止と全接続回収を確認する。
ホスト原本の生成・公開・配備手順も最終成果物と照合する。既存の本人login担当は変更しない。

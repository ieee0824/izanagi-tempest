# M3 派生 Debian イメージ

実VMの owner/firewall/doas、配送、M2操作の検証を行った。結果と検査の限界は
[M3 検証記録](../docs/M3-IMAGE.md)を参照。成功した Packer ビルドだけでは隔離の証明にならない。

## 固定入力とビルド

macOS arm64、QEMU (HVF)、Packer と QEMU plugin、Python 3.11+、Rust、
Zig と cargo-zigbuild を使用する。Izanagi は
`16d0b55947006a166cfa29dcb8bfe71f65f8c36a`、LWS は
`2c0ea463f334f10a562e54f1cdc7ba8a474029e2` の clean checkout にする。
agent、HTTP sidecar、host CLI、BPF ELF の固定 checkout とビルドコマンドは
[M0 のビルド入力](../tools/m0/image/README.md#ビルド入力)に従う。
LWS は別の clean checkout で、vendored SQLCipher/OpenSSL を含めてビルドする。

```bash
git clone https://github.com/ieee0824/lws.git /private/tmp/tempest-m3-lws-source
git -C /private/tmp/tempest-m3-lws-source checkout 2c0ea463f334f10a562e54f1cdc7ba8a474029e2
cargo zigbuild --manifest-path /private/tmp/tempest-m3-lws-source/Cargo.toml \
  --locked --release --target aarch64-unknown-linux-gnu
```

`--lws` にはこの checkout の `target/aarch64-unknown-linux-gnu/release/lws` を渡す。
ISO は固定版 Packer の SHA-256 と照合し、別バージョンへ自動更新しない。

```bash
python3 -m venv /private/tmp/tempest-m3-venv
/private/tmp/tempest-m3-venv/bin/pip install -r image/requirements.txt
cargo zigbuild --locked --release -p tempest-guest --target aarch64-unknown-linux-gnu
python3 image/prepare.py \
  --izanagi-source /absolute/path/to/izanagi \
  --lws-source /absolute/path/to/lws \
  --iso /absolute/path/to/debian-13.7.0-arm64-netinst.iso \
  --agent /absolute/path/to/izanagi-agent \
  --ebpf /absolute/path/to/izanagi-ebpf \
  --http /absolute/path/to/izanagi-http-capture \
  --lws /absolute/path/to/linux/lws \
  --guest target/aarch64-unknown-linux-gnu/release/tempest-guest \
  --output /private/tmp/tempest-m3-build-001
cd /private/tmp/tempest-m3-build-001/packer
packer init debian.pkr.hcl
packer validate -var-file=tempest.pkrvars.json debian.pkr.hcl
packer build -var-file=tempest.pkrvars.json debian.pkr.hcl
```

成果物は `output-debian/debian-aarch64.qcow2`。
`inputs.json` と guest `/etc/tempest/image.json` に固定 commit、入力と導出スクリプトの
SHA-256、helper version、作成日時、Rust source tree digest/dirty flag、インストール後のバイナリ digest と Debian package version を保存する。
入力 ELF の architecture と source checkout の固定は検査するが、外部から渡した LWS/agent ELF が
その source から作られたことを `prepare.py` だけで証明するものではない。ビルドログも保持する。
ビルド用 root 認証と SSH は上流 lock-down/verify-image により除去する。

## 実VM試験

リポジトリに戻り、ホスト用の固定 Izanagi CLI を指定する。

```bash
/private/tmp/tempest-m3-venv/bin/python integration/image_smoke.py \
  --izanagi /absolute/path/to/host/izanagi \
  --image /private/tmp/tempest-m3-build-001/packer/output-debian/debian-aarch64.qcow2 \
  --output /private/tmp/tempest-m3-run-001
/private/tmp/tempest-m3-venv/bin/python -m unittest discover -s tests -v
```

標準レイアウトの build `inputs.json` と guest の metadata/digest を照合する。
別レイアウトなら `--build-inputs /absolute/path/to/inputs.json` を指定する。
ホストにも PCAP 解析用の tcpdump が必要。出力は新規のホスト専用ディレクトリ (0700)。`summary.json` の個別結果と
`guest-evidence/` を調べ、未検査項目を成功扱いしない。
`restrict_network=true` / read-only 9p / snapshot のまま動かす。
実 AWS、実データ、常用資格情報を投入しない。

## 配送契約

固定 Izanagi CLI の exec は stdin を転送しない。
`transport.py` は read-only 9p の `.tempest-control` に host が要求を発行する。
QEMU mapped-xattr により guest root 所有の directory 0700 / file 0600 にする。
host 実ファイルも 0700 / 0600 とする。Mailbox は VM 起動前に作成し、
親ディレクトリの root mapping が確定してから要求を発行する。
一時ファイルも最初から root0700 の inbox 内に `.tmp` として作り、root owner/mode の設定後に
`.json` へ rename する。ホスト UID が guest agent と一致しても、所有者変換前の本文を公開しない。guest の実測でこの mapping が成立しない構成は採用しない。
共有ルート以外へ scenario や期待値を公開しない。従来の空 sandbox 方針に対する
**root 専用 mailbox だけの例外**であり、agent へ共有する入力置き場にはしない。

root の `tempest-mailbox.service` が新規要求を自律処理する。
公開 doas entry `/usr/local/bin/tempest-guest deliver /workspace/.tempest-control/ID.json` は、
既に生成された暗号化応答の読取りだけを行い、要求の読取り・実行・nonce 消費はしない。
watcher 自体は doas の許可対象にしない。任意の shell/config/native helper も許可しない。

要求 ID は内容に依存しない 128-bit 乱数。root-owned private file を同一 fd で検査・読取りし、
操作別の入力型と token digest を検証する。token は native helper の stdin へ渡し、
seed/probe 入力は root 専用一時ファイルを finally で削除する。
要求を処理する前に root の nonce ファイルを排他的に作成・fsync し、同じ要求を二度実行しない。
reply key は要求ごとの独立した 256-bit key。応答 JSON を65536 bytesへ pad し、
AES-GCM (nonce 96-bit、AAD は version/ID/operation) で暗号化する。
doas stdout やその FD から暗号文が見えても復号鍵を持たない主体へ本文を公開しない。
argv/env には token、reply key、scenario 本文を入れない。

要求上限8 MiB、fetch は allowlist の3ファイルのみ、chunk 上限32768 bytes。
暗号化応答は約88 KiBで固定 Izanagi の512 KiB出力上限内に収める。
chunk と全体の SHA-256/長さを host が照合する。巨大な manifest 等が応答枠を超えた場合は
明示的に operation uncertain として扱い、成功した切詰め結果を返さない。
応答喪失後は同じ ID の保存済み暗号文だけ取得する。
状態変更操作を新 ID で自動再送しない。確定不能ならその VM/run を破棄する。
host は応答受領後に要求ファイルを削除する。途中失敗時の残留は host private directory 内に限定し、
run 終了後に廃棄する。guest 側 nonce/reply は使い捨て snapshot 内に残り、次の VM へ持ち越さない。

起動時は owner firewall と root control supervisor を準備する。
LWS/proxy は専用 lws UID、capture は root。HTTP listener と capture は M2 の seal で開始し、
export で最終化する。起動時に tcpdump を開始しない。
agent の子孫終了と export 順序を含む M4 の lifecycle 全体は別途 #5 の責務となる。

M4用派生イメージは `attest` とidentity付き `export` により、daemonをfreezeしたまま
子孫終了確認・native exportを行う。旧M3イメージとはexport要求が異なるため、同じ版のscriptを使う。
実装順序、固定hash、2回のVM検査と未確認範囲は [M4終了確認](../docs/M4-QUIESCE.md)を参照。
`integration/image_smoke.py` に `--tempest /absolute/path/to/tempest` を加えると、
測定GETを独立MCP supervisor/bridgeへ流し、予算未転送とRPC drainからexportまでを確認する。
専用dummy HMACとbinary snapshotをrun内に保持する。成功・失敗例と制約は
[M4 supervisor](../docs/M4-SUPERVISOR.md)を参照。

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

## Linux x86_64 向け導出（実VM検証待ち）

`prepare.py --architecture x86_64` は固定上流の Debian template の実bytesを検査し、
ELF machine=62（eBPFのみ247）、QEMU `/usr/bin/qemu-system-x86_64` / q35 / KVM、
Debian 13.7.0 amd64 ISO、BIOS installer の `/install.amd` へ導出する。
省略時は従来のaarch64を使用する。上流checkoutは変更しない。
ISOは[公式署名検証](https://www.debian.org/CD/verify)を行い、
固定SHA256 `a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355`
と実bytesを照合してから使用する。prepareはhash検査のみで、署名検証を代行しない。

Packer pluginは1.1.8、HTTP/SSH/VNCは127.0.0.1の18082/22222/5902へ固定する。
guestのHTTP取得先はSLIRP host alias 10.0.2.2である。agentはeBPF feature付き、
HTTP/LWS/tempest-guestはx86向けの別artifactを用意し、build commandとlock/hashを保持する。

```bash
python3 image/prepare.py --architecture x86_64 \
  --izanagi-source /absolute/path/to/pinned-izanagi \
  --lws-source /absolute/path/to/pinned-lws \
  --iso /absolute/path/to/debian-13.7.0-amd64-netinst.iso \
  --agent /absolute/path/to/x86_64/izanagi-agent \
  --ebpf /absolute/path/to/izanagi-ebpf \
  --http /absolute/path/to/x86_64/izanagi-http-capture \
  --lws /absolute/path/to/x86_64/lws \
  --guest /absolute/path/to/x86_64/tempest-guest \
  --output /private/tmp/tempest-x86-image-definition-001
python3 -m unittest discover -s tests -p test_image_x86.py -v
```

固定入力のx86 full image生成とlock-down検査は
[試行003の記録](https://github.com/ieee0824/izanagi-tempest/blob/ac88482/docs/LINUX_X86_FULL_BUILD_003.md)
で確認した。実kernel引数と無人インストール完走を観測している。
実guestのeBPF採取とowner/firewall/doas/mailboxのdummy検査は
[smoke002](https://github.com/ieee0824/izanagi-tempest/blob/8ddf75f/docs/LINUX_X86_IMAGE_SMOKE_002.md)
で確認した。固定構成の観測範囲であり、全route・全lifetimeの完全性を意味しない。
HTTP sidecar実起動とpositive control付き外部到達拒否は未検証のまま残す。
image生成成功だけを本番相当VMの受入に置き換えない。
実build前には専用userのroot所有・非write入力snapshotと回収可能な単発commandを監査する。

固定ISOはinclude先`spkgtk.cfg`で30秒後にspeech installerを起動するため、
x86派生の`boot_wait`は10秒とする（#41）。元upstreamとarm64の60秒設定は変更しない。
serial出力とkernel consoleを有効にし、`quiet`を外して起動段階を記録する。
固定plugin1.1.8はQEMUのcwdを変更しないため、`installer-serial.log`は
専用unitのprivate work directoryへ書かれる。実行前に同file不在を確認する。
Packer debugも新private logへ保存し、全文をroomやGitへ公開しない。

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

## exec応答の目印検査

固定dummy試験でhost CLIのexec stdout/stderrを追加検査する場合は、次を使う。

```bash
python3 integration/image_smoke.py \
  --izanagi /absolute/path/to/pinned/izanagi \
  --image /absolute/path/to/tempest.qcow2 \
  --build-inputs /absolute/path/to/inputs.json \
  --output /private/tmp/tempest-exec-exposure-001 \
  --exec-evidence
```

`exec-evidence/`は0700、stdout/stderrと操作種別・returncode・timeoutの記録は0600で保存する。
各execの返却前に既知のdummy管理token・reply key・private payload目印を検査し、最後に全目印で再検査する。
timeoutの部分出力も保存する。漏出時は応答を後続処理へ渡さず失敗し、raw証拠をprivateに保持する。
`summary.json`の`checks.exec_private_markers`は件数・操作種別・漏出file名だけを記録し、目印値を含めない。
従来のevents/alerts/up stdout/stderrの検査とは別の証拠であり、native helperのPIPEや全`/proc`の
cmdline/env/FD・全期間の露出を検査したことにはしない。原本streamやdummy keyを公開しない。

## actorからの限定proc観測

`--exec-evidence --proc-evidence`を併用すると、claim前・seed後・export前の3時点で、
guest actor UID1000から`/proc`のcmdline/environとFD一覧件数を読み取る。FDの内容は読まない。
/proc採取前にroot所有・非writeの`/etc/tempest/image.json`と固定Izanagi/LWS commitを確認する。
helperの直接実行は固定guestだけに限定し、hostではsynthetic fixtureのみを使う。
公開canaryをargvと初期envへ渡し、観測process自身で両方が読めたことと、自身のFD一覧取得をpositive controlとする。
private管理tokenやreply keyをprobeへ渡すことはしない。

PID/starttime集合を最大4096件まで列挙し、127対象＋観測自身1PIDのページへ分割する。
1ページ128PID・各stream8192B・応答128KiBの上限を保ち、最大33ページ＋列挙1回、
各時点の総応答34×128KiB以内とする。欠落・重複・別page/identityの結び付けは拒否する。
切詰め・想定外error・control不成立はcompleteにしない。列挙後のPID消滅・再利用・不安定なidentityは
対応件数へ明記し、元のidentityを観測できたと数えない。coverageは全列挙要求への対応であり、
全identityの存続・読取成功を意味しない。

秘密を含まない`proc_evidence.py`と`proc_paging.py`だけを、検証用read-only共有領域へ起動前に0444で配置する。
setup/expect/資格情報は含めない。guest Pythonは`-I -B`で固定helperを実行し、公開canaryとpage対象だけを渡す。
raw snapshotはprivateなexec応答証拠だけへ保存し、summaryには件数・状態・control結果だけを載せる。
exec応答のdummy目印scanが、観測できたcmdline/env本文にも適用される。
これは3時点のpaged observationであり、同時点の全process・短命native・全期間・FD内容の非露出を証明しない。
128PID上限で失敗したproc-exposure001は保持し、ページ方式は別の計画・固定入力で実測する。

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

## export配送競合の専用試験イメージ

`image/prepare.py` の通常引数に `--delivery-race-fixture` を追加すると、通常イメージとは別に、
実root `deliver` の待機をquiesceが確認してからfreezeする試験用イメージを導出する。
fixtureの有無と実際に導出したscriptのhashをinputs/image metadataへ記録する。
通常buildに待機やrendezvousは追加しない。試験イメージを通常のモデル評価へ用いない。

ビルド後、同じ専用flagで実VM試験を行う。

```bash
python3 integration/image_smoke.py --izanagi /absolute/path/to/izanagi --image /private/tmp/tempest-delivery-race-build-001/packer/output-debian/debian-aarch64.qcow2 --build-inputs /private/tmp/tempest-delivery-race-build-001/inputs.json --output /private/tmp/tempest-delivery-race-run-001 --delivery-race-fixture
```

実root readerのPIDがquiesceの`moved_pids`へ含まれること、読取失敗を観測した後に同じ要求IDの
認証済み応答を取得できることを検査する。要求の再投入は行わない。失敗応答は本文を転記せず
種別・終了コード・stdout/stderr hashだけを記録する。これは配送障害の再現試験であり、
本番controllerの再試行契約や期限・監査の検証を代替しない。

host controllerの回復と失敗上限は、同じfixtureで次を実行する。
`--expect aborted` は修正前のhost binaryの基準確認用である。

```bash
python3 integration/runtime_delivery_race.py --tempest /absolute/path/to/tempest --izanagi /absolute/path/to/izanagi --image /private/tmp/tempest-delivery-race-build-001/packer/output-debian/debian-aarch64.qcow2 --image-inputs /private/tmp/tempest-delivery-race-build-001/inputs.json --python /absolute/path/to/python3 --runs /private/tmp/tempest-delivery-race-fixed-001 --expect completed
python3 integration/runtime_delivery_race.py --tempest /absolute/path/to/tempest --izanagi /absolute/path/to/izanagi --image /private/tmp/tempest-delivery-race-build-001/packer/output-debian/debian-aarch64.qcow2 --image-inputs /private/tmp/tempest-delivery-race-build-001/inputs.json --python /absolute/path/to/python3 --runs /private/tmp/tempest-delivery-race-large-001 --expect completed --large-evidence
```

大証跡caseは1MiBのローカルdummy objectを29回読み、64MiBのhost上限に近いPCAPを作る。
上限付近のサイズ・29要求の保持・認証済みexport・freeze時間・安全回収を検査する。

### HTTP sidecar専用のloopback検査

`integration/image_smoke.py --sidecar-evidence --exec-evidence` は、固定Izanagiのbehavior sidecarをguest内loopbackのfixtureだけで検査する専用モード。
通常の必須引数（`--izanagi`、`--image`、`--output`、必要な`--build-inputs`）を指定し、VM前の固定計画・専用root/UID/snapshot監査を経て実行する。
`--proc-evidence`、`--tempest`、`--delivery-race-fixture`との同時指定は拒否する。
ネットワーク制限とread-only共有を保ち、分類器はmock/allow_export=false、proxy18080、許可fixture19090、対照receiver19091をguest loopbackに固定する。
公開sourceは`proc_evidence.py`と`sidecar_probe.py`だけをguest root所有/0444へmapped配置する。秘密や任意targetをhelperへ渡さない。

共通の起動・artifact/権限・共有検査後、通常M3のclaim/seed/API/PCAP試験を実行せず、専用receiver/clientへ分岐する。
sidecarのproxy環境注入が通常M3のloopback通信へ干渉するためであり、M3成功の代替とはしない。
receiverへの直接対照、許可fixtureへのproxy転送、許可Hostの別port拒否、非許可Host拒否を、status・dummy body応答・receiver件数で照合する。
拒否時client statusは固定版では502。別portはpolicy=allowed/outcome=failed、非許可Hostはpolicy=denied/outcome=rejectedとして区別する。

公開nonce/actor/sidecar PID-starttime/guest bootと有限観測区間をprivate execへ保存し、receiver thread/socketを同一execで回収する。
終了後に唯一のfresh behavior sessionのbounded auditをprivate保存し、client socket→request ID→outcome、boot/session/source、bytes・privacyと拒否時upstream0を照合する。
bodyをmetadataへ保存した場合は失敗する。exec/log/behaviorの管理目印scanは保持する。
全期間のsidecar可用性、稼働exe hashの直接読取、writer attribution、分類精度、外部egress、実model/credentialをこの検査で保証しない。
この実装の追加だけでは実VM成功を意味せず、固定単発VMの結果を別に監査する。

固定Linux sidecar001の単発結果は[検証範囲](../docs/SIDECAR-EVIDENCE.md)を参照する。正常転送/2種類の拒否とmetadataを確認済みだが、外部egressや#36全体の受入とは別である。

# M3 VM イメージと管理入力の配送

2026-11-12 JST。#4 の実装と実VM検証記録。
ビルドと実行のコマンド、依存、サイズ上限、障害時処理は [image/README.md](../image/README.md)。
ホストの `tempest run` / MCP proxy / モデルアダプタは #5 以降であり、今回の実装に含めない。

## 構成と入力の固定

固定 Izanagi `16d0b55947006a166cfa29dcb8bfe71f65f8c36a` の Debian 13.7.0 arm64
Packer 定義から派生する。上流 checkout と既存イメージは変更しない。
Homebrew / anyenv / Node の追加を省き、LWS、AWS CLI、tcpdump、iptables、doas、
Python と cryptography、Rust native helper と固定 Python mailbox consumer を追加する。
LWS は固定 `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` の Linux aarch64 release。

起動順は owner firewall → root control supervisor → root mailbox consumer → Izanagi agent。
LWS と HTTP proxy は専用 lws UID、データと記録は0700。
4567 は root/lws UID のみ許可し、それ以外の loopback TCP を拒否する。
root control socket と token digest は `/run/tempest-control` 内。
LWS は seed、HTTP listener と root capture は seal、有限 drain/停止・manifest 確定は export で行う。
VM 起動時に tcpdump を開始しない。

検証環境: macOS arm64/HVF、guest Debian、guest izanagi UID1000、lws UID999/GID989。
guest package は awscli 2.23.6-1、tcpdump 4.99.5-2、iptables 1.8.11-2、
opendoas 6.8.2-1+b1、Python 3.13.5-1、python3-cryptography 43.0.0-3+deb13u1。
`restrict_network=true`、9p は read-only、ディスクは snapshot のまま。実 AWS には接続しない。

## 配送の境界

固定 exec は stdin を転送しない。管理 token / setup / probe と応答鍵は
host の私有作業ディレクトリから read-only 9p の root 専用 mailbox に渡す。
agent から読める scenario や期待値を共有しない。
従来の空 sandbox 方針は、この root 専用 mailbox に限って例外とする。
macOS の QEMU は host の `sizeof(mode_t)`（16bit）で mode xattr を読むため、
mode は2byte、uid/gidは4byteの little endian で設定する。Linux host の mode は4byte。
実VMの owner/mode 検査に失敗した構成は採用しない。

要求を実行するのは root 常駐 consumer だけであり、公開 doas entry は要求を読まない。
既知 ID に対して返すのは保存済みの固定長 AES-GCM 暗号文のみ。
管理 token と応答鍵を argv/env に置かず、root→native は stdin を使う。
同じ入口 UID から要求内の token を補って native を呼ぶ旧案は、代理実行を防げず撤回した。
応答取得は非破壊であり、鍵/nonce を使って再暗号化せず保存済み暗号文を返す。
応答喪失時は同じ ID で取得し、状態変更を別 ID で自動再実行しない。

## 実VMで確認した結果

最終イメージ `build-006`、run `run-006`。収集器の `collected_requires_review` は
自動収集完了を示すだけであり、以下は収集内容と実装を照合して確認した範囲。

| 要件・境界 | 結果・根拠 |
|---|---|
| 固定入力→guest の一致 | host `inputs.json` と guest `image.json` の commit/source tree/input/derivation digest を照合。guest 内の実ファイル digest も一致 |
| claim / seed / probe / seal / export / fetch | 一連の操作成功、出力3ファイルの長さと SHA-256 一致 |
| claim 再発行・不正 token・seal 後 seed | 拒否。誤 token の後に正規 seed 成功 |
| probe の分類 | 既知の worker に対し200 allow、403 AccessDenied、501 NotImplementedを保持 |
| read-only と権限 | mailbox root0700、要求0600、非rootの要求openは EACCES。公開テスト領域0777への書込みも EROFS |
| backend の owner 制限 | root probe は成功。UID1000から4567の接続は拒否。LWS UIDは999。seal後のUID1000→4566→LWSは成功 |
| 私有データと control socket | UID1000から data/evidence/state 読取りと control socket 接続を拒否 |
| proc と FD | LWSの environ 読取り拒否。root mailbox PID の fd 列挙・environ・mem 読取りを EACCES/EPERM で拒否 |
| doas の範囲 | /bin/true、native helper直接実行、watch起動、tokenなしseedを拒否 |
| 既知 ID の取得攻撃 | claim/seed/export要求の鍵を読めない。同UID3プロセスから並列取得しても同一暗号文。再取得後もhostが復号でき、読み取りで消費されない |
| 残存子孫 | 親の正常0/timeout124/異常137終了後に子が生存。各90回の私有領域openを拒否、その間ping成功。対象子が停止/ゾンビであることをexport前に確認 |
| 記録境界 | seal前4566は接続不可。測定JSONLは2件のagent GETのみ、seed/probeを含まない |
| 短時間 PCAP | seal直後とexport直前の異なるGETと各応答本文をPCAP内で確認。4566/4567双方をtcpdumpで解析、33 packets、drop0、5150bytes |
| 終了順 | recorder停止→capture停止→finalized manifest。capture immediate mode、HTTP/API不完全・ingress lossなし |
| argv/観測ログ | 実token、各応答鍵、私有入力の目印をevents.log/alerts.log/up stdout/stderrで検査し、該当なし |
| 残留 | host mailboxの要求JSONは終了後0件。guest状態・nonce・暗号文は使い捨てsnapshot内。down完了を確認 |

初期イメージでは TCP reset 拒否ルールに `-p tcp` がなく、boot時firewallが失敗した。
修正後はビルド時にも実ルールの作成/サービス起動を必須検査にした。
また短い測定では tcpdump のbufferが届かず、HTTP1件なのにPCAP24bytes/captured0でも
complete=trueとなった。`--immediate-mode -U` を指定し、HTTP観測ありでpacket0/ヘッダーのみなら
不完全にする。空capture故障注入の回帰試験も追加した。
この条件は全欠落の検出であり、packet非ゼロだけで任意の通信の完全性を証明するものではない。

## 証跡の結び付け

イメージ内ソースは `63f3da5d5dcbdb46c1a019430ca3d5d24f08889d`、Rust source dirty=false。
ホスト収集器は同ブランチの追補で境界検査を追加したもの。
Git外の私有証跡は `.m0-evidence/20261112-m3/`。
元の build/run は `/private/tmp/tempest-m3-20261112/` 内。
イメージ本体は build-006/packer/output-debian/debian-aarch64.qcow2 に保持する。

| 対象 | SHA-256 |
|---|---|
| Rust source tree | `2283cfc8cc53b75b17fc0f51f37717e2a638d756805aa975800a85d10962e7c1` |
| Linux guest helper | `1c9ed1f98a16d9ad3c83f81a9f757c128d3a8845d15d68b088278eb77508c97c` |
| Linux LWS | `aca61cb0899ecd92a1f4c324c716a7e17e9166cf07af0d084986d9973031dc37` |
| build inputs.json | `c72dd255371d6d271de04230cda79aaef00a88578e9d873fd0743c97f773f39f` |
| 最終イメージ | `4e925ba5bef9aa3c9a0c660e42211ffb7235d9280f63638d8aaac8865d5b389a` |
| host Izanagi CLI | `d7f896b71241da81e81d99e6d4f7b974f867705df5cf5ca4163e8f461632fa34` |
| run-006 summary | `491950e366c5b71c3b9645c639885bb3ef478c25539c706964dbb9a6e13912d8` |
| api.jsonl | `399223c6ed477336370dd99befa1410446ea712983bd95d4ae4d1a3574e6cd49` |
| capture.pcap | `28d643f407c8671968d6b1c64d394a908c42627eb3a9817d7fc30f51a3037d16` |
| manifest.json | `6a7d282afef9d5e33ca1fb85b3d283e113212cd6a5cda28cf0c424c67b3ec92d` |

## 検査の限界と後続

Rust21件、Python16件、実LWS/tcpdumpのホスト結合12件、fmt/clippy、Linux aarch64 buildが成功。
実VMの権限検査とホストdevelopmentモードの試験を区別する。
VMでの検査は上記の固定構成・操作・観測対象についての結果。
全プロセスの全FD、全サイズ/障害の組合せ、timingの非干渉、root consumer強制終了や
ホスト回収失敗の全途中状態まで網羅したものではなく、#13の広い配送調査は閉じない。
一般のエージェント子孫の検出/強制停止・回収順序は #5 で実装する。
M2 manifest の `complete_scope=recorder_internal` と `agent_route_enforcement=not_verified` は維持し、
この限定された試験を任意エージェントの迂回不能や評価結果の証明へ広げない。

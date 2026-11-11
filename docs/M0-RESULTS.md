# M0 実測記録

更新日: 2026-11-11。状態: **M0 完了（固定したローカル構成での実測）**。
本体ハーネス・M1 以降は未実装。

最終判定は [最終実測と Issue #1 の確認結果](#最終実測と-issue-1-の確認結果)、
機械可読な要約は [M0-EVIDENCE.json](M0-EVIDENCE.json) を参照。
以下の初回・途中記録にある未確認事項は、その段階の状態であり、最終実測で補完した。

## 初回（2026-11-01）の実行環境と結果

| 項目 | 実測値 |
|---|---|
| Izanagi | `izanagi 0.2.7` |
| QEMU | aarch64 / x86_64 とも `11.1.2` |
| 設定 | `tools/m0/izanagi.example.toml` |
| 設定 SHA-256 | `a9f4aca04bfc8774e1ae2cbfde1038c04506343a35baf7ec9204ab0219bc5222` |
| 制限 | QEMU / vm-agent、認証必須、`restrict_network=true`、空 cwd の読み取り専用共有 |
| 前提確認 | バージョン取得成功 |
| `up --pcap` | 終了コード 1、`Operation not permitted (os error 1)` |
| 後処理 `down` | 終了コード 1、「izanagi は起動していません」 |

起動拒否の具体的な箇所は未特定。イメージは `default` 指定で、ハッシュ・コミットは
未固定のため、今回の記録は起動前の調査結果としてのみ扱う。
認証を無効化したり、ネットワーク制限を解除したりする回避は行っていない。

## 証跡

ローカルの非公開ディレクトリに保存。再実行時は別の出力先を使う。

- `/private/tmp/tempest-m0-preflight-20261101/summary.json`
- `/private/tmp/tempest-m0-boot-20261101/summary.json`

収集 JSON はコマンド、開始・終了時刻、終了コード、標準出力・標準エラーを含む。
キーの値は収集しない。ログや PCAP は点検なしにリポジトリへ追加しない。

## 初回時点の未確認と再開条件

loopback の syscall・PCAP、API の成功・403・501、ホストツール隔離、
cwd と MCP セッションの対応、共有マウント、時計の出どころはすべて未確認。
Izanagi と QEMU が動作可能な環境で起動失敗の原因を確認し、イメージを固定して
収集ツールを再実行する。その後、IMPLEMENTATION.md 9.1 の検証を行う。


## 2026-11-11 の再検証

まず既存インストール版で調べ、その後、固定コミットから構築したイメージで補完した。

認証必須・`restrict_network=true`・共有 `read_only=true` を維持し、
Codex の実行制限外で QEMU を起動した。制限内では同じ構成で
`Operation not permitted` を再現し、制限外では起動・exec・停止が成功した。
したがって実行制限による拒否が今回の再現条件である。拒否されたシステムコール自体は未特定。

収集ツールにも独立した問題があった。`izanagi up` は起動後に終了せず、停止まで待つ。
旧ツールの `subprocess.run(..., timeout=90)` は正常稼働中の supervisor を強制終了していた。
修正版は `Popen` で保持し、起動通知後の認証付き exec で準備完了を確認する。
起動通知より前の exec は自動起動と競合するため呼ばない。
`down` の後に supervisor の終了も待つ。途中の競合試行で残った検証用 QEMU は
cwd と PID を確認して停止した。別プロジェクトの Izanagi には操作していない。

### 固定した成果物

- Izanagi: `0.2.7`、実行ファイル SHA-256
  `41a43bfe3c37bbbd7e2f0fa9f0fc51a1ac628045401da612984ebc894aad802b`
- QEMU: `11.1.2`。実行ファイルの SHA-256 は各 `summary.json` に記録
- イメージ: `/Users/ast/.izanagi/images/debian-aarch64.qcow2`
- イメージ SHA-256: `6ed63a3306f7de27e01cd7c49320d015ee135e475bdbaa35078c7bd344f8df2b`
- 設定 SHA-256: `8ccb3500d6eb3e1b63d16b2c8ed6ef9fdced7f916f6599af811d8a864cdb726c`
- 上記バイナリとイメージの由来のコミットは未確認。別途参照した Izanagi ソースの
  HEAD を、実行バイナリのビルド元とはみなさない

### 手順・期待値・実測値

`collect.py --boot --guest-probe tools/m0/guest-basics.sh` を実行。
このスクリプトの HTTP は通信確認用であり、LWS の成功・403・501 の代替ではない。

| 項目 | 期待値 | 実測値・判定 |
|---|---|---|
| 起動・停止 | 認証付き exec が成功し、down と supervisor が正常終了 | `boot-005` / `boot-006` で成功 |
| exec ユーザー | 非 root | uid/gid 1000 `izanagi` |
| cwd と MCP | 同じ cwd だけが対象 VM に接続 | CLI で VM の `/tmp` に作成した乱数マーカーを同じ cwd の MCP が読み取った。別 cwd の status は `running:false`。この構成で確認 |
| 共有マウント | 専用 cwd を共有、書き込み不可 | `/workspace` に 9p。作成試行は EACCES。ホスト cwd が 0700 のため、read_only 設定単独による拒否の証明にはならない。mount 表示は rw |
| 時計 | ゲスト epoch とホスト区間を比較可能 | `date +%s%N` を3回記録。ゲスト UTC 09:29:59 に対してログは18:29:59で、ホストの JST と整合。イベント時刻の生成元は未確認 |
| loopback syscall | 接続先と実行を観測できる | curl の execve、`connect(127.0.0.1:53927)`、閉じたポート40751への connect が events.log に存在 |
| 接続結果 | 成功と拒否を区別 | HTTP 本文を受信。閉じたポートは Python で errno 111。一方 syscall ログは両方 `err=115` を含むため、これだけで API の成否を決められない |
| 制御 PCAP | ファイルと形式を確認 | 24 bytes、linktype 147 (`LINKTYPE_USER0`) のヘッダーのみ。今回のファイルから通信内容の記録成功は確認できない |
| ゲスト側キャプチャ | loopback PCAP を取得 | tcpdump・sudo・doas が見つからず未確認 |
| LWS API | 実 LWS で成功・403・501を比較 | LWS・AWS CLI が見つからず未確認 |
| エージェントのホスト隔離 | canary 読み書き等を機構的に拒否 | 未確認。MCP の cwd 分離とは別項目 |

### 証跡と残作業

- `/private/tmp/tempest-m0-20261111/boot-005/summary.json`
- `/private/tmp/tempest-m0-20261111/boot-006/summary.json`
- `boot-006/izanagi-logs/events.log`、`alerts.log`、`control.pcap`

各 summary はホストの開始・終了 epoch ns、コマンド、結果、MCP の要求と応答を含む。
秘密鍵の内容は転記しない。一時領域のため永続保存先への退避は別途必要。

M0 完了には、ゲスト初期化方法の実測、ビルド元コミットの固定、LWS と CLI を使った
API 比較、ゲスト loopback PCAP、イベント時計の生成元、実エージェントのホスト隔離が残る。


## LWS とエージェント CLI の追加実測

### LWS API

公式リポジトリのコミット `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` を一時領域に取得し、
`cargo zigbuild --release --locked --target aarch64-unknown-linux-gnu` でビルドした。
LWS ソースは変更していない。バイナリ SHA-256 は
`aca61cb0899ecd92a1f4c324c716a7e17e9166cf07af0d084986d9973031dc37`。

`collect.py --guest-file <Linux版lws> --guest-probe tools/m0/guest-lws.sh` で実行。
ホストの共有・通信経路は追加せず、認証付き exec で分割転送し、ゲスト側でも SHA-256 を照合した。
VM 内の uid 1000 で LWS を strict 起動し、ダミー管理者識別子で seed した。
この調査用構成はユーザー分離・記録プロキシをまだ持たず、Phase 1 の防御成立を示すものではない。

| 操作 | Python HTTP | curl | エラーコード |
|---|---|---|---|
| 許可された public.txt の GetObject | 200 | 200 | なし |
| 許可されていない private.txt の GetObject | 403 | 403 | AccessDenied |
| strict 未対応のバケット notification 取得 | 501 | 501 | NotImplemented |

`events.log` に LWS ポート56711への接続と curl の execve を確認。
PCAP は再び24 bytesの制御ヘッダーのみであり、API の成否は HTTP 結果から判定した。
AWS CLI 経由の比較、記録プロキシの結果、ゲスト PCAP との対応付けはまだ確認していない。
証跡は `/private/tmp/tempest-m0-20261111/boot-007/summary.json` と同ディレクトリのログ。

### エージェントのホストツール拒否

CLI のモデル接続先を loopback の決定的 API スタブに向け、実モデル・実クラウドには接続せず実行した。
`tools/m0/probe-agent.py` が再実行手順を実装する。canary は agent-cwd の外に置き、
その乱数値はプロンプトに渡していない。スタブがホストの読み取り・書き込みツール呼び出しを
強制的に返すことで、モデルが自主的に操作を避けるだけの結果と区別する。
生のモデル入力・認証ヘッダー・環境変数は保存せず、ツール一覧とツール結果だけを収集する。

| CLI | 設定と結果 |
|---|---|
| Codex 0.167.1、shell_tool のみ無効 | view_image とアプリ連携等がツール一覧に残る。これだけでは不十分 |
| Codex 0.167.1、probe-agent.py の DISABLED 一覧を無効 | 一覧は request_user_input のみ。exec_command / apply_patch / view_image はすべて unsupported call。canary 不変、新規ファイルなし |
| Claude Code 2.1.319、bare・tools 空・strict-mcp-config・setting-sources 空等 | ツール一覧は空。Bash / Read / Write はすべて No such tool available。canary 不変、新規ファイルなし |

Codex の追加無効化項目は、apps / view_image / multi_agent / plugins / remote_plugin /
plugin_sharing / plugin_discovery_prefetch / skill_search / skill_mcp_dependency_install /
hooks / goals / image_generation。設定項目は
[OpenAI の公式設定リファレンス](https://learn.chatgpt.com/docs/config-file/config-reference)と
インストール済み CLI の `features list`・`exec --help` を照合した。
Claude Code の引数はインストール済み `--help` と実行結果で確認した。

証跡:

- `/private/tmp/tempest-m0-20261111/codex-canary-002/summary.json`
- `/private/tmp/tempest-m0-20261111/claude-canary-002/summary.json`

この試行では MCP を追加していない。実 VM への MCP を加えた構成でも同じ拒否が成立し、
許可ツールだけが動くこと、追加ツール経由の迂回がないことは引き続き確認する。
CLI 起動時に読み込まれる情報まで遮断する証明でもないため、情報境界全体の合格とは扱わない。


## 最終実測と Issue #1 の確認結果

実行日: 2026-11-11。最終 run: `boot-011`。以下の7項目と IMPLEMENTATION.md 9.1 を
証跡から手動で確認した。収集ツールの `status: unverified` は自動合否判定を実装していないため維持する。
この記録の M0 完了判定と、各コマンドの終了コードは区別する。

### 固定した最終構成

| 項目 | 値 |
|---|---|
| Izanagi ソース | `16d0b55947006a166cfa29dcb8bfe71f65f8c36a`、クリーンな clone |
| LWS ソース | `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` |
| ホスト Izanagi SHA-256 | `d7f896b71241da81e81d99e6d4f7b974f867705df5cf5ca4163e8f461632fa34` |
| 完成イメージ SHA-256 | `9ed963db17f1c8b6cd282af57b9f34d48031fae8bfe9c8fd85f8af121ef94052` |
| 設定 SHA-256 | `92bda6eaf7b51ebb41a17395f35aceaea360268edeb16e6bdf4513002ead038e` |
| Debian ISO SHA-256 | `6e93fa1759bd9d4b0fc11e938987de6967ee7de5297dac1be27c3a75cc17024b` |
| QEMU | `11.1.2` |
| 制限 | QEMU / vm-agent、認証必須、restrict_network=true、専用の空 cwd だけを read_only で共有 |

ホスト・ゲスト agent・eBPF・HTTP sidecar は固定した Izanagi コミットから新規ビルドした。
生成された eBPF Cargo.lock を含む lock と各バイナリの SHA-256 を保存した。
Izanagi / LWS のソースは変更していない。派生 Packer 定義の生成手順は
[M0 調査用イメージ](../tools/m0/image/README.md)に記載する。
Packer の validate と build は成功し、最終化で `IZANAGI_IMAGE_SECURITY_OK` を確認した。
実測前後のイメージ SHA-256 は一致し、snapshot による実験でベースを書き換えていない。

### 7項目の対応表

| # | 確認項目 | 手順・実測・判定 |
|---|---|---|
| 1 | 起動時初期化を追加する方法 | 上流の Packer file / shell provisioner を派生定義で追加し、systemd unit を enable。再起動後の `/run/tempest-m0/startup.uid` は0、epoch は1794392012511836751。キャプチャと backend も自動起動。**確認済み** |
| 2 | 起動完了の検知 | up を常駐プロセスとして保持し、起動通知後の認証付き exec のマーカーを確認。MCP status でも同一 PID が running:true。down と supervisor は正常終了。**確認済み** |
| 3 | ログの時計・TZ | 固定ビルドの eBPF tracer がゲストの CLOCK_REALTIME − CLOCK_MONOTONIC を使って epoch を生成し、ホストの Local TZ で表示する実装と、実測 epoch / ログを照合。ホストは UTC+09:00。3回の計測でゲストはホスト区間より約21〜31ms先。**確認済み** |
| 4 | loopback syscall | Python HTTP・curl・AWS CLI の接続、execve、backend 4567への拒否試行を events.log で確認。HTTP結果とゲスト PCAP の対応も確認。**確認済み** |
| 5 | cwd と MCP セッション | CLI がゲスト `/tmp` に作った乱数マーカーを、同じ cwd の MCP が読める。別 cwd の status は running:false。実 CLI アダプタ経由でも対象 VM の status / exec / shell を確認。**確認済み** |
| 6 | CLI を MCP だけに限定できるか | Codex 0.167.1 / Claude Code 2.1.319 の組み込みツールを無効化し、ホスト操作をスタブから強制要求。拒否と canary 不変を確認し、許可した MCP は成功。追加経路も下記の範囲で拒否。**確認済み** |
| 7 | cwd の共有とマウント先 | `/workspace` に9p共有。通常の権限拒否を除外するため、0700の証跡親ディレクトリ内の空共有だけ0777にしても作成は EROFS（errno30）。read_only の実効性を確認。**確認済み** |

時計の生成元の根拠は固定コミットの `src/ebpf_tracer.rs:152,246`、
agent の `Message::Event` 転送、`src/log_formatter.rs:94`。
受信時のホスト時計でイベント時刻を置き換える構造ではない。
コマンド開始・終了のホスト epoch ns とゲスト epoch ns は summary に保持している。

### 観測・欠落の対応

API プローブは同じ worker と同じポリシーで Python HTTP / curl / AWS CLI を順に実行した。
GET の成功本文は `dummy-data`。AWS CLI の失敗は終了コード254とエラーコードを記録し、
HTTP ステータス自体は生 HTTP 結果と PCAP で確認した。

| 操作 | API 結果 | syscall | 制御 PCAP | ゲスト loopback PCAP |
|---|---|---|---|---|
| public.txt の許可 GET、3経路 | 200、AWS CLI は終了0 | connect、CLI の execve | ヘッダーのみ | 3経路の GET / 200を確認 |
| private.txt の拒否 GET、3経路 | 403 AccessDenied | connect、CLI の execve | ヘッダーのみ | 403が3件 |
| 未対応 notification、3経路 | 501 NotImplemented | connect、CLI の execve | ヘッダーのみ | 501が3件 |
| root 専用 backend の接続拒否 | LISTEN=true、root health=ok / strict に対し uid1000 の connect_ex は errno111 | port4567への connect（err115を含む） | ヘッダーのみ | 試行時刻に該当するパケットなし |

backend 4567は実 LWS が root で稼働し、OUTPUT の owner ルールで非 root を REJECT する。
単なる未起動ポートへの拒否試行とは別に確認した。
PCAP 内の4567宛通信は起動時 root health の既存フローで、最終パケットは epoch1794392026.003804。
拒否プローブは epoch1794392030.197以降であり、その試行に対応するパケットは存在しない。
パケット不在を「試行なし」とは扱わない。

ゲスト PCAP は29,005 bytes、linktype1（Ethernet）、制御 PCAP は24 bytes、linktype147。
最初の回収では libpcap のバッファに残った末尾の AWS CLI 通信を取りこぼしたため、
最終回収はプローブ終了後1.5秒待ち、実パケットの403 / 501が各3件になることを確認した。
Izanagi の制御 PCAP は本構成の証跡の主軸にせず、API 結果とゲストキャプチャを採用する。

### ホスト隔離の確認範囲

実 VM の MCP を加えた最終構成で、両 CLI とも8回のスタブ応答を処理して終了0。
以下の拒否応答と、親側での canary 不変・新規書き込みファイルなしを突き合わせた。

- Codex: exec_command / apply_patch / view_image は unsupported call。
- Claude Code: Bash / Read / Write は No such tool available。
- 許可した sandbox_status は running:true、sandbox_shell の id は1000。
- sandbox_exec / sandbox_shell にホスト canary の絶対パスを渡しても VM 内では存在せず、読み書きは失敗。
- Codex の resources/read に file URI を渡す経路は Izanagi の Method not found で失敗。
- Claude Code の未登録 `mcp__other__read` もツール未提供として失敗。

この範囲で M0 のホストツール隔離を確認した。実モデルのベンチマークや将来の CLI 版の保証ではない。
モデル、CLI、設定、プラグインが変わる場合は再検証する。
MCP プロキシ・seed 専用トークン・本体のユーザー分離は後続 M2〜M4 の実装対象である。

### 保管と再現

一時領域の消失に備え、リポジトリ内の非公開ローカルディレクトリ
`.m0-evidence/20261111/` に次を退避した。このディレクトリは Git の対象外。

- `boot-011/summary.json`、CLI ごとの summary、events / alerts、両 PCAP
- 比較用 `boot-009` / `boot-010`
- `image-build/packer.log`、派生 Packer 定義、`inputs.json`、各 Cargo.lock
- 固定バイナリと完成イメージ、SHA-256 を記録した `manifest.json`

認証シークレットファイルは保管・公開対象に含めない。
公開可能な要約とハッシュは [M0-EVIDENCE.json](M0-EVIDENCE.json) に保持する。
再実行は新しい出力ディレクトリとダミーの認証キーを使い、イメージとバイナリの絶対パスを指定する。

# M0 実測の収集

本体の Rust workspace に先立つ、Python 3.11 以降・標準ライブラリのみの調査用ツール。
本体 CLI や M0 の自動合否判定はまだ実装していない。

## 前提確認

```bash
python3 tools/m0/collect.py --output /private/tmp/tempest-m0-preflight-001
python3 -m unittest discover -s tests -v
```

出力先は毎回新しいディレクトリにする。`summary.json` にバージョン、時刻、終了コード、
標準出力・標準エラーを保存する。VM を起動しない前提確認でも、M0 の判定は `unverified` のまま。

## QEMU 起動とインベントリ収集

`izanagi.example.toml` を参考に設定を用意する。`image` は固定イメージの絶対パスに変更し、
その SHA-256 と由来のコミットを実験記録に残す。既存の認証キーを使う場合は値を出力せず、
保護されたファイルのパスを `IZANAGI_SECRET_FILE` に設定する。

```bash
export IZANAGI_SECRET_FILE=/path/to/protected/secret
python3 tools/m0/collect.py \
  --output /private/tmp/tempest-m0-boot-001 \
  --config /absolute/path/to/izanagi.toml --boot
```

空の `sandbox/` を cwd にして `up --pcap` を常駐プロセスとして起動する。
起動通知後の認証付き exec で準備完了を確認し、ゲストのユーザー・時計・マウント・
ツール一覧、同じ cwd と別 cwd の MCP 応答を取得して `down` する。
失敗・タイムアウト時にも `down` を試し、起動プロセスの終了を待つ。
実行ファイルと、絶対パスで指定されたイメージの SHA-256 も保存する。
`up.stdout` / `up.stderr`、run に対応する `izanagi-logs/` も証跡に含む。
停止失敗時はログを確認し、同じ cwd・設定でセッションの残存を確認する。
起動成功だけでは loopback 観測やホスト隔離を合格にしない。

QEMU / vm-agent・認証必須・ネットワーク制限・共有の読み取り専用を明示しない設定は拒否する。
共有対象は専用 cwd のみ。生のログ・PCAP は公開せず、秘密情報の点検後に必要な結果だけを転記する。

## 次の検証

`docs/IMPLEMENTATION.md` 9.1 に従い、LWS の成功・403・501 と backend 拒否について
API 結果・syscall・制御 PCAP・ゲスト loopback PCAP を比較する。
その後にアダプタのホスト操作遮断を検証する。これらは本ツールでは未実装。


## ゲストの基礎プローブ

```bash
python3 tools/m0/collect.py \
  --output /private/tmp/tempest-m0-basics-001 \
  --config /absolute/path/to/izanagi.toml --boot \
  --guest-probe tools/m0/guest-basics.sh
```

`--guest-probe` は指定したシェルスクリプトを使い捨てゲストで実行する。
基礎プローブは Python 3 と curl を使い、共有へのダミーファイル作成試行、
sudo / doas の存在、loopback の HTTP 接続と閉じたポートへの接続を JSON で出力する。
HTTP サーバーは通信確認専用であり、LWS の認可結果を模擬するものではない。
共有への書き込み拒否が EACCES の場合、共有の read_only 設定による拒否とは断定しない。

MCP の確認では CLI でゲストの `/tmp` に乱数マーカーを作り、同じ cwd の MCP から読む。
別 cwd では status とツール一覧だけを取得し、VM を自動起動しない。
生の応答を残す方式で、`collected` は合格を意味しない。
時計もホスト側のコマンド開始・終了 epoch ns とゲストの epoch ns を残し、
イベント時刻の生成元とは区別して検討する。


## 実 LWS の API プローブ

Linux aarch64 向けの固定 LWS バイナリを用意し、コミット・ビルド手順を記録する。
2026-11-11 のビルド条件は [実測記録](../../docs/M0-RESULTS.md#lws-api) を参照。

```bash
python3 tools/m0/collect.py \
  --output /private/tmp/tempest-m0-lws-001 \
  --config /absolute/path/to/izanagi.toml --boot \
  --guest-file /absolute/path/to/linux/lws \
  --guest-probe tools/m0/guest-lws.sh
```

`--guest-file` はファイル名を保って `/tmp/tempest-m0-assets/` に分割転送する。
共有や VM のネットワーク許可は増やさず、転送後の SHA-256 を検証する。
転送コマンドの payload は summary で省略し、各分割の offset・長さ・SHA-256 を記録する。
`guest-lws.sh` は名前が `lws` の実行ファイルを使い、strict の200・403・501を
Python HTTP と curl で比較する。AWS CLI・recorder・ゲスト PCAP の代替にはしない。

## エージェント CLI の組み込みツール拒否

```bash
python3 tools/m0/probe-agent.py --agent codex --output /private/tmp/tempest-m0-codex-001
python3 tools/m0/probe-agent.py --agent claude --output /private/tmp/tempest-m0-claude-001
```

対応 CLI のインストールとホスト loopback の listen が必要。実モデルや API キーは不要。
CLI に loopback の API スタブを指定し、非対話実行で host canary の読み書きを要求する。
出力先は毎回新規にする。ツール一覧、強制要求、拒否応答、canary の変化を summary に保存する。
終了コード0は CLI の正常終了を示すだけで、M0 の合格とはみなさない。
実 MCP を接続した構成や追加ツール経由の迂回検証は別途必要。


実 VM の MCP を加えて確認する場合は、次のように指定する。

```bash
python3 tools/m0/collect.py --output /private/tmp/tempest-m0-agent-vm-001 \
  --izanagi /absolute/path/to/pinned/izanagi \
  --config /absolute/path/to/izanagi.toml --boot \
  --agent-probe codex --agent-probe claude
```

許可した status の成功に加え、exec / shell にホスト canary のパスを渡しても
VM 内では見つからず、ホストファイルが変化しないことを確認する。
Codex の resources/read と、Claude Code の未登録 MCP ツールも迂回として要求する。
`--probe-share-readonly` は0700の証跡ディレクトリ内の空共有だけを0777にして、
通常のアクセス権と read_only による拒否を区別する。ネットワーク・共有の設定は弱めない。

起動時サービス・AWS CLI・ゲストキャプチャが必要な場合は
[M0 調査用イメージ](image/README.md)を構築し、`--guest-capture` で回収する。
最終リクエストの libpcap バッファ処理を待ってから PCAP を読み出すが、
各操作が含まれるかは必ずパケット内容で確認する。

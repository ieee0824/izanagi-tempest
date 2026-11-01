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

空の `sandbox/` を cwd にして `up --pcap`、ゲストのユーザー・時計・マウント・
ツール一覧の取得、`down` を順に実行する。失敗・タイムアウト時にも `down` を試す。
停止失敗時はログを確認し、同じ cwd・設定でセッションの残存を確認する。
起動成功だけでは loopback 観測やホスト隔離を合格にしない。

QEMU / vm-agent・認証必須・ネットワーク制限・共有の読み取り専用を明示しない設定は拒否する。
共有対象は専用 cwd のみ。生のログ・PCAP は公開せず、秘密情報の点検後に必要な結果だけを転記する。

## 次の検証

`docs/IMPLEMENTATION.md` 9.1 に従い、LWS の成功・403・501 と backend 拒否について
API 結果・syscall・制御 PCAP・ゲスト loopback PCAP・ファイアウォール拒否記録を比較する。
通常の syscall ログは connect の宛先・戻り値を持たない。backend への迂回は遮断と拒否記録を
別々に検証し、PCAP や警告の不在を試行なしの根拠にしない。
その後にアダプタのホスト操作遮断を検証する。これらは本ツールでは未実装。

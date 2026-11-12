# izanagi-tempest

**AI エージェントにクラウド環境を攻撃・検証させ、その過程を監視して評価するローカルセキュリティ実験基盤**

[Izanagi](https://github.com/ieee0824/izanagi)(AI エージェント用サンドボックス)と
[LWS](https://github.com/ieee0824/lws)(ローカル AWS シミュレータ)をつなぐオーケストレーション層です。

> M0 の実測、M1 のシナリオ静的検証、M2 のゲストヘルパーを実装しています。VM イメージ整備とホストの実行・評価ハーネスは後続です。設計の詳細は [docs/DESIGN.md](docs/DESIGN.md) を参照してください。

## 何をするもの

AI エージェント(Claude / Codex 等)に、意図的に誤設定を投入した模擬 AWS 環境(LWS)への攻撃を仕掛けさせ、
その全過程を Izanagi が監視します。

```
AI Agent / Orchestrator
        │ MCP
izanagi-tempest (シナリオ / seed / 評価 / レポート)
        │
Izanagi (攻撃VM: eBPF・PCAP・検知ルール) ◄──► LWS (模擬AWS: S3/SQS/SES/IAM strict)
```

1. **シナリオ**: 誤設定(例: 非公開バケットも読める過剰権限ポリシー)と期待値を YAML で定義
2. **実行**: エージェントが Izanagi の MCP 経由で AWS CLI を操作し、権限の境界を探索
3. **観測**: syscall・通信(PCAP)・API の Allow/Deny 結果をすべて記録
4. **評価**: 期待値との比較 + 権限範囲の逸脱行動の検知
5. **報告**: 再現可能なレポートを生成

## 目的

- 権限昇格・認可境界の突破・データ流出経路の**自動検証**
- 攻撃過程の完全な証跡化と再現可能なレポート
- 同一シナリオでの**モデル間比較**(発見率・誤検知率・試行回数・逸脱行動)— AI Red Team ベンチマーク基盤

## スコープと制約

- 検証対象は LWS の模擬範囲(S3 / SQS / SES / IAM)**のみ**。すべてローカルで完結し、実 AWS に接続しない
- LWS は SigV4 を検証しないため、**認可(authorization)のテストに限定**。認証突破は対象外
- LWS の IAM は部分実装(AssumeRole / STS / Condition / バケットポリシー未対応)のため、
  シナリオは identity ベースポリシーの範囲で設計する

## ロードマップ

| Phase | 構成 | 内容 |
|---|---|---|
| 1 | Izanagi VM 内に LWS を同居 | 最小 PoC。シナリオ→実行→評価→レポートのフロー構築(loopback 完結、ネットワーク制限は解除しない) |
| 2 | 攻撃側と LWS 側を別 VM に分離 | 通信を LWS エンドポイントに限定するブリッジを追加。「攻撃側から LWS 以外へ到達できない」こと自体を検証対象に |
| 以降 | 拡張 | 脆弱な Web アプリを前段に置いた複合シナリオ、行動分析の拡張 |

## ドキュメント

- [設計ドキュメント](docs/DESIGN.md) — アーキテクチャ、シナリオフォーマット、実行フロー、評価メトリクス、制約事項
- [実装設計 (Phase 1)](docs/IMPLEMENTATION.md) — Rust による実装構成、VM 内の記録・防御、判定ロジック、テスト計画、マイルストーン

## 開発: M0 の前提確認

Python 3.11 以降で、追加依存なしに実行できます。

```bash
python3 tools/m0/collect.py --output /private/tmp/tempest-m0-preflight-001
python3 -m unittest discover -s tests -p test_m0_collect.py -v
```

QEMU の起動・証跡収集の手順は [M0 収集ツール](tools/m0/README.md)、
最終実測結果と観測上の制約は [M0 実測記録](docs/M0-RESULTS.md) を参照してください。
Rust のビルド・シナリオ検証は次節を参照してください。

M0 の基礎プローブと、実モデルを使わない CLI ツール拒否の検証も実装しています。
後者には対応する CLI とホスト loopback の listen 権限が必要です。

```bash
python3 tools/m0/probe-agent.py --agent codex --output /private/tmp/tempest-m0-codex-001
python3 tools/m0/probe-agent.py --agent claude --output /private/tmp/tempest-m0-claude-001
```

VM の `--guest-probe`・`--guest-file`・`--agent-probe` と固定バイナリ指定 `--izanagi` の手順は
[M0 収集ツール](tools/m0/README.md)を参照してください。

## 開発: M1 のシナリオ静的検証

Rust edition 2024 の toolchain と Cargo が必要です（Rust 1.99.0 / macOS arm64 で検証）。
依存は Cargo.lock に固定しています。初回は crates.io への接続が必要です。

```bash
rustup toolchain install stable --component rustfmt --component clippy
cargo build --workspace --locked
cargo run --locked -p tempest -- validate scenarios/s3-overread-001.yaml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

成功時は JSON に ID、元ファイルのバイト列の SHA-256、固定 LWS commit、
`validation: "static"`、finding / retest の有無、budget を出力します。
非空 deviation は保持し `deviation_semantics_unchecked: true` と表示します。
成功は静的な構造・ポリシー構文・API・リソース参照検証を意味します。
認可・finding・retest・VM 隔離の実行結果は `runtime_checks: "not_performed"` です。

終了コードは成功0、検証エラー1、引数・ファイル読み込みエラー2です。
検証エラーはフィールド経路と理由を stderr に出し、パーサー由来の行・列があれば併記します。

`crates/tempest-model` が共有型と静的検証、`crates/tempest` が YAML 読み込みと CLI、
`crates/tempest-guest` は次節のゲストヘルパーです。ホストの `tempest run` はまだありません。
API 対応表は [capability.rs](crates/tempest-model/src/capability.rs) に固定ソースの根拠を集約し、
未知・strict 未対応・現入力形式では必要条件を表せない操作を区別します。
ポリシーの wildcard は保持し、IAM の認可評価は実装しません。

入力契約・実装順序は [M1 計画](docs/M1-PLAN.md)、パーサー選定の比較は
[YAML 実測](docs/M1-YAML-PROBE.md) を参照してください。

## 開発: M2 のゲストヘルパー

`tempest-guest` に recorder / claim / seed / probe / seal / export を実装しています。
root の制御 supervisor と専用 uid の HTTP proxy / LWS を分け、seal で記録を開始します。
本文をJSONLに保存せず、転送中の長さ・SHA-256、API推定、status / error_code と未完了を記録します。
probe は allow / deny / unsupported / error、export は complete / 欠損を明示します。
設定と正確な状態・配送・権限の契約は [M2 ヘルパー](docs/M2-GUEST.md)、
VM 用設定例は [examples/guest.json](examples/guest.json) を参照してください。

実 LWS の結合試験には、非rootの Unix ホスト、AWS CLI v2、tcpdump と loopback capture の権限が必要です。
LWS のビルドには C toolchain・make・Perl が必要です（SQLCipher / OpenSSL を同梱ビルド）。
固定ソースを別ディレクトリへ取得して実行します。

```bash
git clone https://github.com/ieee0824/lws /private/tmp/tempest-m2-lws-source
git -C /private/tmp/tempest-m2-lws-source checkout 2c0ea463f334f10a562e54f1cdc7ba8a474029e2
cargo build --manifest-path /private/tmp/tempest-m2-lws-source/Cargo.toml --release --locked
cargo build --locked -p tempest-guest
python3 integration/guest_smoke.py --lws /private/tmp/tempest-m2-lws-source/target/release/lws
```

一時データ・空きport・ローカルのダミー資格情報だけを使い、実 AWS へ接続しません。
ホスト試験は development モードであり、VM の doas・owner 制限やホスト→VMの秘密配送の実証とは分けます。
配送の残る調査は [Issue #13](https://github.com/ieee0824/izanagi-tempest/issues/13) で追跡しています。

## 開発: M3 の VM イメージ

固定 Debian テンプレートからの派生イメージと root 専用 mailbox を実装中です。
ビルド・実VM検証のコマンドと配送契約は [image/README.md](image/README.md) を参照してください。

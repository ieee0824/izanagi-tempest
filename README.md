# izanagi-tempest

**AI エージェントにクラウド環境を攻撃・検証させ、その過程を監視して評価するローカルセキュリティ実験基盤**

[Izanagi](https://github.com/ieee0824/izanagi)(AI エージェント用サンドボックス)と
[LWS](https://github.com/ieee0824/lws)(ローカル AWS シミュレータ)をつなぐオーケストレーション層です。

> ⚠️ M0 の検証基盤を実装中です。本体ハーネスは未実装。設計の詳細は [docs/DESIGN.md](docs/DESIGN.md) を参照してください。

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
python3 -m unittest discover -s tests -v
```

QEMU の起動・証跡収集の手順は [M0 収集ツール](tools/m0/README.md)、
初回の実行結果と未確認事項は [M0 実測記録](docs/M0-RESULTS.md) を参照してください。
本体の build / run コマンドはまだありません。

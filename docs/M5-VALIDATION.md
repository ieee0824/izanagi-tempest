# M5 検証状況

Issue #6 / PR #31。以下は完了宣言ではなく、現行実装と確認済み証拠の対応である。

| 要件 | 検証 | 状況 |
|---|---|---|
| finding・expect判定表、501、主体照合 | `evaluate.rs` 単体試験 | 確認済み。未知の資格情報は認証成功とは表示しない |
| findings抽出・不正値・重複JSON | `evaluate.rs` 単体試験 | 確認済み。小文字allow/deny以外はschema不正 |
| 時計補正・区間重複・背景 | `timeline.rs`、`report.rs` 単体試験 | 確認済み。背景は帰属未解決として保持 |
| Izanagi形式変更・解析不能 | `izanagi_log.rs`、背景/破損fixture | 確認済み。未解釈行を完全性診断へ反映 |
| deviation overrideとcall単位重複除去 | `deviation.rs` 単体試験 | 確認済み。deny優先、不正overrideはunavailable |
| 通常mock・fresh retest・reset | `integration/runtime_smoke.py` | freeze対応イメージで通常2回成功 |
| 4567・doas seed・LWS状態アクセス拒否 | 同上boundary run | freeze対応イメージで成功、4種候補を計上 |
| 評価成果物の確定と読取整合性 | 排他・hash・必須集合・改変fixture | 確認済み。readerは共有lock下で検証したbytesを使用 |
| 評価時run入力の保存 | snapshot不変fixture | 確認済み。最終化後のrun.json変更と独立 |
| guest要求ID・失敗監査 | ID重複/欠損/拒否/overflow/順序反転fixture | 更新イメージの正常2回・防御1回も成功 |

## 実VM証拠

- `/private/tmp/tempest-m5-freeze-e2e-001/`: 通常2回・境界拒否1回の実行成功。
- `/private/tmp/tempest-m5-host-audit-runs-001/normal-audit/`: host管理要求監査の実行成功。
- `/private/tmp/tempest-m5-request-audit-e2e-001/`: 要求ID監査入りイメージで正常2回・防御1回成功。正常結果の要求ID一致と失敗操作記録なしを確認。

私有run directoryにはcredential claimを含む証跡があり、リポジトリへ複製しない。
上記パスはこの検証環境の所在であり、他環境で存在するとは限らない。

## 未完了の照合

- 最新評価器による確定成果物の再検証。
- optional finding/retestの4通りと、aborted/部分証跡に対する最終結果の接続試験。
- 未確定背景候補と正式適格性の契約。時刻相関だけで主体を確定しない。
- 最新headの全検証とPRレビュー所見の最終照合。

rootによるstate/manifest改変や、ログから識別できない直接操作を検出したとは主張しない。
この制約は [実装設計](IMPLEMENTATION.md) 6.3 の観測下限・信頼境界と合わせて読む。

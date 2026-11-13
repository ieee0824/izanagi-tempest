# M5 検証状況

Issue #6 / PR #31。以下は現行実装と確認済み証拠の対応である。

| 要件 | 検証 | 状況 |
|---|---|---|
| finding・expect判定表、501、主体照合 | `evaluate.rs` 単体試験 | 確認済み。未知の資格情報は認証成功とは表示しない |
| 非ASCII Authorizationとquery AKIDの選択 | recorder単体fixture | 単体のみ。0x80を含むAuthorizationとquery AKIDが実HTTP経路でLWS認可・記録まで一致することは未検証 |
| 主体不明の成功をunknownとして保持 | `evaluate.rs` 単体試験 | 単体のみ。実VMでの当該異常経路の注入は未検証 |
| findings抽出・不正値・重複JSON | `evaluate.rs` 単体試験 | 確認済み。小文字allow/deny以外はschema不正 |
| 時計補正・区間重複・背景 | `timeline.rs`、`report.rs` 単体試験 | 確認済み。背景は帰属未解決として保持 |
| Izanagi形式変更・解析不能 | `izanagi_log.rs`、背景/破損fixture | 確認済み。未解釈行を完全性診断へ反映 |
| deviation overrideとcall単位重複除去 | `deviation.rs` 単体試験 | 確認済み。deny優先、不正overrideはunavailable |
| 通常mock・fresh retest・reset | `integration/runtime_smoke.py` | freeze対応イメージで通常2回成功 |
| 4567・doas seed・LWS状態アクセス拒否 | 同上boundary run | freeze対応イメージで成功、4種候補を計上 |
| 評価成果物の確定と読取整合性 | 排他・hash・必須集合・改変fixture | 確認済み。readerは共有lock下で検証したbytesを使用 |
| 評価時run入力の保存 | snapshot不変fixture | 確認済み。最終化後のrun.json変更と独立 |
| guest要求ID・失敗監査 | ID重複/欠損/拒否/overflow/順序反転fixture | 更新イメージの正常2回・防御1回も成功 |
| finding/retest省略4通り | `integration/runtime_presence.py` | 全4通りの実VM試験成功。not_configured/not_performedを区別 |
| 中断・破損証跡の自動評価 | `integration/runtime_faults.py --case evaluation` | seed応答喪失・fetch破損でpartial/unknown/nullと確定済み成果物を確認 |

## 実VM証拠

- `/private/tmp/tempest-m5-freeze-e2e-001/`: 通常2回・境界拒否1回の実行成功。
- `/private/tmp/tempest-m5-host-audit-runs-001/normal-audit/`: host管理要求監査の実行成功。
- `/private/tmp/tempest-m5-request-audit-e2e-001/`: 要求ID監査入りイメージで正常2回・防御1回成功。正常結果の要求ID一致と失敗操作記録なしを確認。
- `/private/tmp/tempest-m5-final-report.qca34l/`: 最新評価器で上記3runの私有コピーを再評価。通常2回はいずれもfound/retest passed/ID matched、確定候補0・未確定11。防御runは候補計上を保持。各世代は入力snapshotと出力hash付きで確定。
- `/private/tmp/tempest-m5-presence-e2e-001/`: finding/retestの全4通りが成功。
- `/private/tmp/tempest-m5-evaluation-faults-001/`: seed応答喪失・fetch破損の部分評価検査が成功。

最新headのRust全テスト・Clippy・fmt、Python 19件が成功。上記再評価3世代の
入力snapshot・result・report・timelineの計12ファイルは、marker記録hashとの一致を直接確認済み。

私有run directoryにはcredential claimを含む証跡があり、リポジトリへ複製しない。
上記パスはこの検証環境の所在であり、他環境で存在するとは限らない。

## レビューと後続検証

Sakura投稿15350の最終レビューを反映し、単体試験と実経路の検証範囲を上表で区別した。
何もしないmockの反復対照による背景未確定候補の基準記録は未実施であり、
#7でモデルrunを解釈する前に取得する。基準と一致しても主体を確定したとは扱わない。

未確定背景候補は保持し、指標側をunknownとする。全体の正式適格性はfalseだが、
対象runを分母から削除せずunknown数を残す契約である。findingの観測は保持する。
候補数を真の逸脱率とは表示せず、集計はM6で実装する。

rootによるstate/manifest改変や、ログから識別できない直接操作を検出したとは主張しない。
この制約は [実装設計](IMPLEMENTATION.md) 6.3 の観測下限・信頼境界と合わせて読む。

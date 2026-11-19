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

## 現在の再検証との区別

上記は当時の検証報告であり、私有パスの存在やhashを現在再測定できたという意味ではない。
新しい固定x86 imageでは[正常2回/reset](LINUX_X86_RUNTIME_NORMAL_001.md)を保存証拠付きで確認した。
finding/retestの4presenceも新imageで実施済みであり、下記に保存証拠と限界を示す。

[seed-loss001](LINUX_X86_RUNTIME_SEED_LOSS_001.md)は成功seed返信の喪失、agent未開始、VM廃棄を確認したが、
同run ID拒否の検査がCLIのstdout/stderr契約と不一致でtrial全体は失敗した。
旧scriptには削除済みbridgeによるENOENTを拒否成功と誤認し得る問題と、失敗seed返信でも注入する問題もあった。
PR #47/#48で修正したが、旧報告の同ID拒否や適用成功をその修正だけで遡及認定しない。
#15は既存runへの[VMなし予約拒否追加証拠](LINUX_X86_RUNTIME_RESERVATION_001.md)と正常2回・主体/競合検証を合わせて完了条件を満たし、close済み。旧seed-loss trial自体の失敗と旧retry出力欠測は保持する。
mockの部分評価成功と正式モデル比較の適格性は引き続き区別する。

## 固定Linux x86での4presence再検証

#14はPR #39でDESIGN/IMPLEMENTATIONの4presence・未実施理由・別分母を接続し、
PR #46で実probe監査、PR #51で実行前比較計画のbindingを検査へ追加した。
[固定Linux presence001](https://github.com/ieee0824/izanagi-tempest/blob/1b8c44d/docs/LINUX_X86_RUNTIME_PRESENCE_001.md)
と[選別結果](https://github.com/ieee0824/izanagi-tempest/blob/1b8c44d/docs/LINUX_X86_RUNTIME_PRESENCE_001_RESULT.json)
をsource/collectorと照合した。

| finding/retest | primary probe開始/完了 | finding結果 | retest結果 | VM数 |
|---|---|---|---|---|
| 有/有 | 同ID各1 | found | passed | 2 |
| 有/無 | 同ID各1 | found | not_performed / not_configured | 1 |
| 無/有 | 各0 | not_configured | passed（独立policy検証） | 2 |
| 無/無 | 各0 | not_configured | not_performed / not_configured | 1 |

4runはすべてcompleted/evaluation performed。未設定self-check/retestはperformed=falseと省略理由を保持し、
未設定retest directoryは生成しなかった。全resultが実行前の4slot計画へverified bindingされた。
集計採用4件・欠測0件・予定外0件、finding/retestそれぞれ設定済み分母2・not_configured2、
条件横断率はnot_computed、formal eligibleは0である。
6VMのnonce/session/ダミー資格情報の非再利用、回収、1316固定入力と旧証拠の不変を保存した。
caller exit0とobserverのGC終端unknown/exit1を分け、同InvocationのExecStopPost/trusted journalと
独立cgroup/UID/port回収を別証拠として照合した。全route・全lifetimeや実モデル比較の証明ではない。
これは保存結果/sourceの照合であり、MacからLinux実ファイルを再測定したものではない。

## レビューと後続検証

Sakura投稿15350の最終レビューを反映し、単体試験と実経路の検証範囲を上表で区別した。
何もしないmockの反復対照による背景未確定候補の基準記録は未実施であり、
#7でモデルrunを解釈する前に取得する。基準と一致しても主体を確定したとは扱わない。

未確定背景候補は保持し、指標側をunknownとする。全体の正式適格性はfalseだが、
対象runを分母から削除せずunknown数を残す契約である。findingの観測は保持する。
候補数を真の逸脱率とは表示せず、集計はM6で実装する。

rootによるstate/manifest改変や、ログから識別できない直接操作を検出したとは主張しない。
この制約は [実装設計](IMPLEMENTATION.md) 6.3 の観測下限・信頼境界と合わせて読む。

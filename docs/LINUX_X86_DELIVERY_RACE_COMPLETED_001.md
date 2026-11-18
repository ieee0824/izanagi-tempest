# Linux x86固定host CLI配送競合completed001

## 結果と範囲

room16827監査後、固定host Tempest CLIを実管理MCP経路で使うcompleted試験を一度だけ実行した。
caller99801と独立collector21903は各同handleで終了コード0。[安全な結果投影](LINUX_X86_DELIVERY_RACE_COMPLETED_001_RESULT.json)と[collector source](evidence/delivery-race-completed-001/collect_result.py)を保存した。
run.status=completed、evaluation=performed、self-check established、fresh retest configured/performed/checks_passedを確認した。
mockのcallsは0件、API evidenceは0行、finding outcomeはunknown、formal_metrics_eligible=falseである。発見能力・正式比較の成功とは扱わない。大容量controlは未実施。

[固定snapshot](LINUX_X86_DELIVERY_RACE_COMPLETED_SNAPSHOT_001.json)は1310項目、source d5f873b、固定host CLI SHA4354c40b…とfixture image SHA4c2a101c…を保持する。
現HEADから再buildしたbinaryとは記録しない。直前検査70337は終了コード0、free10459947008 bytesで、入力/19source/外部runtime/旧証拠、未使用unit、UID999空、出力不在、KVMを確認した。
監視91578を先行して単発callerを起動し、再試行・旧root再利用はしていない。
unitは`tempest-izanagi-delivery-race-completed-001.service`、Invocationは`55a19055fed94911877b97fcf5be4437`、bootは`30389abc903c40ae89a5c6268ec1c432`。

## 競合回復とreceipt照合

host control operation ID `5b4dbcfe2f486aeff9b1c1b4885c86d6`のexport startedは1件。
同じhost IDの3 readは`reply_unavailable → execution_error → ciphertext_received`で、completedが1件である。
native mailbox export IDは別の`0e00c260bfe5bcb1a5a94a27bd2faa8d`であり、host audit IDと同一値だとは扱わない。
fixed host CLIは実行中に応答を認証・復号し、collectorは鍵を回復せず、保存controlの全関連started集合とguestのauthorized intent集合・control遷移を独立再計算して一致させた。

forced reader PID1118はmoved_pids `[1115,1116,1118]`に含まれる。service_frozen/descendants_empty、frozen_duration_ns=183201526、complete exportとcollection completeを確認した。
export-indexとrun receiptの一致、api.jsonl/capture.pcap/manifest.jsonの実長・SHA、collectionのexpected/observed metadataとverified=true、実manifestとreceipt内manifestの一致を照合した。
このfreeze実測を一般の最大停止時間や大容量時の保証にしない。

## Fresh retestと独立observer

65sampleを固定snapshot内の既存runtime validatorとSessionsへ再適用し、2段階の順序・異なるidentity・各bindingの完備性を独立確認した。

| 段階 | QEMU PID | starttime ticks | workspace |
| --- | ---: | ---: | --- |
| primary | 317055 | 38375020 | runs/forced-delivery-race/sandbox |
| retest | 317378 | 38378150 | runs/forced-delivery-race/retest/sandbox |

各boot nonce/session fingerprint/supervisor PIDはrunのvm_bindingへ一致し、2 VMのnonce/fingerprintとdummy credentialは別である（credential値・hashは公開しない）。
restrict/snapshot/readonly-share条件と単一VM、stage順序・入替拒否を保ち、外部listener観測はない。
observerはunit GC後の同Invocation終端属性を得られず終了コード1。終端はunknownのまま保持し、2 stage完備性はcollectorの独立replayで確認した。

## 終了・回収と限界

ExecStopPostの同Invocation exited0/successと、PID1/root/current boot/同unitのStarting・Started・Deactivated journalで正常終了を確認した。
primary/retestのcompanion/down/management/up cleanupは成功し、forced group stop・missing logsはない。artifact inventory complete、transport-hmacと__pycache__は不在。
専用UID999プロセス・cgroupは不在、観測loopback port40777/45301は閉じている。
1310入力・19source/data・外部runtime・旧入力/結果は不変で、前smokeの削除済み鍵も不在のまま。collector後free10358030336 bytes。

これは固定Linux・固定binary・mock・小容量の競合回復とfresh retestの試験である。
Internet全般、本番B/MCP・実モデル、短命native PIPE/全期間FD内容、すべての配送障害、大容量録画の完全性へ一般化しない。
次は[後続runtime計画](LINUX_X86_DELIVERY_RACE_RUNTIME_PLAN.md)に従い、大容量controlの期待値と容量・新rootを実行前に別監査する。

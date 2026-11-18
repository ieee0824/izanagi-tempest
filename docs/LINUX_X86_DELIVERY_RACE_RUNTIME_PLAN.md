# 固定Linux x86の配送競合再検証計画

## 状態

[build001のビルド・offline照合](LINUX_X86_DELIVERY_RACE_BUILD_001.md)は完了し、room16811で結果監査を受理された。[M3 forced-reader smoke001](LINUX_X86_DELIVERY_RACE_SMOKE_001.md)も単発実行して成功し、room16821で結果監査と専用鍵cleanupを完了した。[固定host CLI completed001](LINUX_X86_DELIVERY_RACE_COMPLETED_001.md)はroom16827監査後に単発実行し、競合回復・fresh retestと独立collectorが成功、結果監査を待つ段階である。以下の3の大容量controlは未実施。
[build計画](LINUX_X86_DELIVERY_RACE_BUILD_001_PLAN.md)の完了をruntime成功の代用にしない。

## ビルド後の開始条件

生成qcow2の実SHA・format・backingなし、fixture=trueのhost/guest metadata、実instrument後dispatcher/quiesce SHAとinstall結果を確認する。
同Invocationの終了記録、callerとobserverの終了状態、UID/cgroup/port回収、固定29入力と旧証拠不変を確認する。observerのGC終端欠測は独立したtrusted終了と分けて記録する。
新runtime snapshotでは完成imageを読取専用入力へ固定し、通常runtimeのrestrict/snapshot/share条件を検査する。installer用buildネットワーク契約を流用しない。
各試験は新root・新unit・新run IDで実施し、正確argv、Python環境、source closure、専用UID権限、空き容量、observerを実行前に固定する。
実モデル/OAuthは使わず、local LWSとdummyデータ・mockのみを使う。

## 試験順序と判定

1. `integration/image_smoke.py --delivery-race-fixture --exec-evidence`でfixture内の実root reader競合を確認する。同export IDの読取失敗と認証済み応答、forced_reader_pidがmoved_pidsに含まれること、freezeと必須M3検査・trace・終了回収を検査する。
2. `integration/runtime_delivery_race.py --expect completed`を固定済みhost Tempest CLIで実施する。primary export投入1回、実管理MCPの読取失敗からの回復、complete export、fresh retest、cleanup、鍵不在、formal_metrics_eligible=falseを要求する。
3. 大容量dummy controlは別rootで計画する。29要求・56〜64MiB PCAP・receiptの長さ/hashを検査する。`--expect completed --large-evidence`を採用する場合はmanifest completeを要求する。recorder欠損が発生したrunを後からcompletedへ変更しない。`--expect collected --large-evidence`はrun aborted・failure=recorder evidence incomplete・manifest incompleteを確認する別の期待値であり、実行前に選択する。

固定host CLIは既存検証のSHA `4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f`を照合して再利用する。現在HEADから再buildしたbinaryだとは記録しない。
修正前binaryによる`--expect aborted`は今回の開始条件に含めず、既存歴史結果を新Linux実測として転記しない。

## 保存する証拠と限界

各caller/observer handleを同じまま終端まで追い、Invocation、QEMU PID/starttime/cwd、runtime隔離条件、入力不変、終了/回収を保存する。失敗partialを保持し、自動retryや既存rootの再利用をしない。
run/control/result/export receiptとprivate execの安全な監査結果を保存し、credential実値・復号鍵は公開しない。
大容量の回収成功は敵対的証跡量全般のfreeze上限、Internet全般、本番B/MCP経路、正式モデル比較の証明にはしない。

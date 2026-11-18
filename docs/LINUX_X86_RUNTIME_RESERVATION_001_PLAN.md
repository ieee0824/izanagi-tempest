# Linux x86 runtime reservation001 計画

## 範囲

草案、未実行。seed-loss001の失敗原本を変更せず、同ID拒否だけをVM無しの別検査として保存する。
旧trialを遡及合格にしない。root /var/lib/tempest-izanagi-runtime-reservation-001、unit tempest-izanagi-runtime-reservation-001.service を新設する。

[固定check](evidence/runtime-reservation-001/check_once.py) のCOMMANDは旧seed-loss001の固定CLI/image/scenario/mock/Pythonと同じ引数を使い、bridgeだけ実在する固定base bridgeを指定する。
同UID999/Group988、env-i/Python-I-Bで30秒以内に一度だけ呼ぶ。既存runs/seed-reply-lossがあることを事前検査する。
PR48のreservation_refusalを新read-only inputsへ固定し、exit1/stdout JSON scope=m5_evaluation/runs=[]/stopped=infrastructure:...EEXISTを要求する。
stdout/stderrは新private evidenceに保存し、公開は安全な判定flag/hashのみ。

## 不変と監視

旧seed-loss001全root（inputs/work/home/tmp/evidence/runsを含む）の通常file内容・mode/owner、directory、symlink target、xattrを前後比較する。
旧normal/full/smoke入力と既存証拠も照合する。旧run.jsonだけの一致で全tree不変を代替しない。
旧raw logs/keysは公開せず、全tree manifestはprivate、公開はmanifest hash/件数/一致flag。
既存failed unitはresetせず、旧unit/cgroupは操作しない。

新root observerは新unit/cgroupのsampleを保存し、QEMUを1つでも観測すれば当該unitを停止する運用とする。
事前/事後はホストQEMUなし、UID999なしを確認する。sampling間の完全な不存在証明とは呼ばず、ソース上の予約失敗がVM生成前であることと別に扱う。
observerはroot所有root直下へread-only readiness markerを作り、checkはmarker後にCLIを起動する。CLI後も2秒生存して最終live sampleを確保する。
PID1/currentboot journal、同Invocation exit recorder、caller/observer各handle、cgroup/UID回収を保存する。

新unitはTypeexec/User999/Group988/KillModecontrol-group/RuntimeMax90/Stop10/Restartno/UMask0077/NNP/Delegate=no。
新work/home/tmp/evidenceはUID9990700、新inputs/rootはroot:988のread-only。
新input closure/hash/mode/owner、旧tree baseline、具体observer/callerと最終preflight監査後に一度だけ実行する。
未知/失敗は部分証拠保持し、暗黙retry/新VM/seed再送は行わない。

## helper実装

[tree inventory](evidence/runtime-reservation-001/tree_manifest.py) は通常fileのSHA・UID/GID/mode・inode/device/link・mtime/ctime、symlink target、xattr hashを記録する。
atimeだけは読取で変わるため比較から除外する。private manifestのraw rowsは公開しない。
[observer](evidence/runtime-reservation-001/observe.py) は100msごとに専用unit sampleとhost QEMU PID一覧をprivate JSONLへ保存し、QEMU観測時は当該unitだけstopして失敗する。
readiness markerはUID999が置換できないroot直下にroot:988/0440で作成する。
構文検査、treeの読取反復一致と内容変更検知fixtureは成功した。まだsnapshot作成・CLI実行はしていない。

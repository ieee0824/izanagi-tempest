# Linux x86 runtime reservation001 計画

## 範囲

実行・回収済み。[結果](LINUX_X86_RUNTIME_RESERVATION_001.md)を参照。seed-loss001の失敗原本を変更せず、同ID拒否だけをVM無しの別検査として保存した。
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

## 未実行v1の準備記録とmarker修正

[準備v1](LINUX_X86_RUNTIME_RESERVATION_PREPARATION_001_V1.json) を保存した。作成caller88326は同handle終端exit0。
全7inputをroot:988/0440へ固定し、旧seed-loss001全tree1537項目のprivate baselineを新rootへ保存した。
ただしroom16630で、observerのumask077によりready mode0440が0400になる点と、公開後writeによる空marker読取raceが指摘された。
v1 observer/CLIは未実行。旧inputs/observe.pyとsnapshot.jsonは保持し、修正版はinputs/observe_v2.pyへ別固定してsnapshot-v2.jsonを保存する予定。
実行はv2とUID999 marker読取/排他公開の検査、最終監査後とする。

実体照合による訂正: 準備開始前のrebaseで83c5a8cが既に入り、v1 inputs/observe.pyは修正済みsourceと完全一致していた（SHA256 2563aaac9b0debad4ca990140d7be3d5d9fc37f3aea7db8b3f70812818cc1a0b）。
旧observerを実行した事実はない。room16634に合わせて実行対象を明示するため、同一修正版bytesをobserve_v2.pyへ別固定した。
実際に残っていた問題は新ROOT/inputsのumask由来0700であり、v1はUID999 traverse未検査の準備失敗として記録する。
prepare sourceへ明示chmod0750を追加し、既存新環境のこの2directoryだけを0750へ是正する。入力file/hashと旧seed-loss全treeは変更しない。

## 最終v2準備

[8入力snapshot](LINUX_X86_RUNTIME_RESERVATION_SNAPSHOT_001_V2.json) と [UID検査v2](LINUX_X86_RUNTIME_RESERVATION_PREPARATION_001_V2.json) を保存。
旧7inputとsnapshot.jsonは保持、新observe_v2.pyだけを追加した。observerはv1と同一の83c5a8c修正版bytesであり、v1未実行のまま実行対象を明示するための追加である。
root/inputsだけ0750へ是正し、旧seed-loss1537項目のbaseline一致を再確認した（caller64644終端exit0）。
全8入力を実UID999でread可/write不可/hash一致、stdlib imports、別test directoryでのroot公開marker0440読取を確認。
新unit not-found/inactive/Invocation空、UID999 processなし、本番observer-ready/observation.jsonl未作成、空き容量39219318784 bytes。

先行observerは `sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-runtime-reservation-001/inputs/observe_v2.py`。
固定callerは `sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-runtime-reservation-001/inputs/run_once.py`。
まだ両方未実行。入力snapshot-v2と具体commandの最終監査後に一度だけ開始する。

# Linux x86 runtime seed-loss001 部分結果

## 判定

trial全体は失敗。caller71954は同handle終端exit1、最後のsame-ID予約拒否検査で `retry did not reach the existing run-ID reservation` assertionが失敗した。
[選別結果](LINUX_X86_RUNTIME_SEED_LOSS_001_RESULT.json) と [collector](evidence/runtime-seed-loss-001/collect_result.py) を保存した。
実retry stdout/stderrは固定scriptが保存しておらず、EEXIST成立は未証明のまま残す。新VMや同ID CLIを追加再実行していない。

## 確認できた範囲

成功応答のdecodeとworker key発行・admin_key_rotated/new_key_verified/old_key_rejectedを検証したwitnessが存在する。秘密値/鍵hashはwitnessに含まれない。
host controlは同一seed IDでstarted1/failed1/completed0。delivery readは35回（reply_unavailable34、最後にciphertext_received1）で、seed requestの再送とは区別する。
run aborted / evaluation partial / finding unknown、agent/export/retestは未開始。artifact inventory complete、一時HMAC/cacheなし。
companionは故意の応答喪失注入で非0終了しcompanion_stopped=false。down/management/up終了は成功、forced group stopなし、missing logなし。

observer6863は1stageのPID/starttime/cwd/session bindingと同Invocation loaded/failed terminalを捕捉し、同handle終端exit0。GC unknownではない。
ExecStopPostとtrusted PID1/UID0/currentboot journalを同Invocation995c31fa97fa45c3aacac0409017bd85へ結び付けた。
cgroup消失、UID999残留なし、観測port35495閉鎖、全1307input/global runtime/旧normal・full・smoke入力証拠不変を独立確認した。
collector26629は同handle終端exit0。

## 原因候補と次段

run_cli.rsはexecuteエラーをstdout JSONのstopped=infrastructure:...へ格納する経路があり、PR47のstderr EEXIST assertionと不一致だった。room16622で実装担当も確認した。
旧retryの実出力は欠測なので、このsource説明だけで旧試験を遡及合格にしない。
修正後は既存IDの拒否だけをVM無しの別記録として検査する具体計画を調整する。
4presence/HTTP sidecar/外部positive control/forced delivery race/全route/正式モデル比較は別gateのまま。実model/credential/AWSは使用していない。

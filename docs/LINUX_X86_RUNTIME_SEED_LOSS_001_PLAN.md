# Linux x86 runtime seed-loss001 計画

## 範囲と状態

草案。snapshot未作成、VM未起動。runtime_faults.pyの偽陽性修正と検査証拠方式の監査が先行する。
#15に関係する、seed適用後の成功応答喪失→agent未開始→VM discardを単発検査する。
root /var/lib/tempest-izanagi-runtime-seed-loss-001、unit tempest-izanagi-runtime-seed-loss-001.service を予約する。
[正常2回結果](LINUX_X86_RUNTIME_NORMAL_001.md) と同じ固定host CLI/Izanagi/image/manifestを使い、core/guest/global設定は変更しない。

## 実行範囲

[固定runner](evidence/runtime-seed-loss-001/run_seed_loss.py) を inputs/run_seed_loss.py に固定し、修正済み runtime_faults.seed_reply_loss だけを実行する。
新runs/seed-reply-lossにprimary VMを1つ起動し、seed成功応答をdecodeした後、controllerへ渡す前に破棄する。
PR47の修正では成功応答/worker key発行/管理鍵ローテーション3flagを検証し、秘密値なしの0600 witnessをruns直下へO_EXCL保存する。host controlのseed started1/failed1/completed0とdelivery read回数を別途照合する。
access_keys/authorization/raw decoded responseを公開しない。未知/失敗応答は適用成功と数えない。
agent/export/retestは開始せず、aborted/partial/unknownとして評価され、VM廃棄・一時material不在・artifact inventoryを検査する。

same run IDの再試行は、実在する固定base bridgeで予約拒否のEEXIST診断とrun.json不変を要求する。
これは新VMのretryではなく、VMを起動せず既存IDを拒否する検査。missing bridgeによる非0を合格にしない。
fetch corruption/SIGTERM/SIGKILL/4presenceは実行しない。

## 固定と独立観測

新root所有read-only inputsへ既存hash固定wheelから専用venvを構築し、host binary/image/CLI/manifest、fault script/mock/scenario、bridge/codec、runner/observer/exit recorderを固定する。
全hash/mode/owner、source/lock/runtime、UID999 read可/write不可、venv/AES/xattr、新runs/exit/log未作成、unit未使用、旧証拠/KVM/容量を監査する。
外側はenv-i/Python-I-B/User999/Group988/kvm993、KillModecontrol-group/Restartno/RuntimeMax1800/Stop10/NNP/UMask0077/Delegate=no。

observerは専用unit/rootと唯一のwork/runs/seed-reply-loss/sandboxを固定する方式を別監査する。
QEMU1台、PID/starttime/cwd、image snapshot=on、readonly mapped share、restrict usernet/loopback、session bindingを検査する。
最終GCはunknownとし、trusted journal/同Invocation exit recorder/cgroup/UID/port回収を別証拠として保存する。
観測違反/timeoutは当該unitだけ停止回収し、部分証拠を保持。暗黙retry・権限緩和は行わない。
具体observer/caller/marker方式とsnapshotの最終監査後に単発開始する。

## 残るgate

4presence、HTTP sidecar、外部到達拒否positive control、forced delivery race、全route、正式モデル比較は未証明のまま。
mock/ダミーのみ、実model/実credential/AWSは使わない。

## 可逆準備の定義

[service](../integration/tempest-izanagi-runtime-seed-loss-001.service)、[固定caller](evidence/runtime-seed-loss-001/run_once.py)、[snapshot helper](evidence/runtime-seed-loss-001/prepare_snapshot.py)、[UID検査](evidence/runtime-seed-loss-001/check_preparation.py) を用意した。
service構文/ExecStart一致とhelper構文を確認済み。未実行で、marker修正とobserverの固定attempt対応が揃ってからsnapshotを作成する。
正常001の全input hash不変照合も新snapshot helperへ追加した。

main27d19bf（PR46/47）を共有branchへmergeした。固定host CLIの元archive全fileのSHAは引き続き照合する。
現treeとの差分はreport.rsのcfg(test) module内追加とseed_controller integration testsだけで、production Rust/Cargo/templateは同一。
seed snapshot helperは旧archive全体と現production sourceを照合し、report.rsはcfg(test)境界前の完全一致を要求する。host CLIは再buildしない。

## observer固定profile

`integration/runtime_normal_observe.py --trial seed-loss --output PRIVATE_NEW_JSONL` を使用する。
`--trial normal`（既定値）は従来の正常系4stage、`seed-loss` は上記専用unit/rootのprimary 1stageだけを許可する。
任意unit/rootの指定は受け付けない。seed-lossでもPID/starttimeとlaunch nonce/sessionのbindingが必要で、
未binding・正常系root/imageの混入・予定外retest・同stageのVM置換は拒否する。
JSONLはsampleとobserved_sessionsを別行で保存し、GC後の終端unknownを成功へ読み替えない。
Mac上のobserver回帰12件（seed-loss 3件を含む）を確認済み。実VMはまだ未実施。

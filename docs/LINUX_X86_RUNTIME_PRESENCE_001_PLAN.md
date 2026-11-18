# Linux x86 runtime presence001 計画

## 範囲と状態

未実行v1 snapshotと専用UID検査は完了。集計計画の接続不足（room16644）のため実行不可、VM未実施。#14のfinding/retest有無4通りを正式runtimeのmockで確認する。
root /var/lib/tempest-izanagi-runtime-presence-001、unit tempest-izanagi-runtime-presence-001.service。
host CLI4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f、Izanagi CLI/image/manifestは正常001/seed-loss001と同じ固定実体をコピーする。
production Rust/guest/image/global設定は変更せず、実model/credential/AWSは使用しない。

## 固定実行と判定

[runner](evidence/runtime-presence-001/run_presence.py) はPR46で補強済みruntime_presence.mainを固定引数で呼び出す。
順序は11 primary/retest→10 primary→01 primary/retest→00 primary、予定6VMのみ逐次実行する。
finding有のprimary probe開始/完了は同ID1回、無は0回、失敗probeなし。configured/performed/省略理由を照合する。
未設定retest directoryを生成せず、設定時はchecks_passed、findingはfound/not_configured、retestはpassed/not_performedを要求する。
6つのVM binding/nonce/session/dummy credential非再利用、固定image、各stage cleanupと一時material不在を追加検査する。

既存tempest report --aggregateを実行しportfolio4runs、finding/retestそれぞれconfigured_denominator2/not_configured2、cross_condition_rates=not_computed、formal_eligible0を要求する。
条件を跨いだ率や正式モデル比較へ昇格しない。原本run/集計/API/PCAP/logはprivate、公開は選別flag/count/hash。

## 固定入力と独立観測

新root所有read-only input closure、hash固定wheel由来の新prefix venv、UID9990700 work/home/tmp/evidenceを作成し、runsはrunnerが新規作成する。
runner/presence script/mock/scenario/bridge/codec/observer/bootstrap/exit recorder、固定CLI/image/manifestを固定する。
observerはruntime_normal_observe.py --trial presence。6stage専用unit/rootとPID/starttime/cwd/launch binding、同時1VM、snapshot/read-only share/restrict/loopbackを検査する。

env-i/Python-I-B、User999/Group988/kvm993、KillModecontrol-group/RuntimeMax1800/Stop10/Restartno/NNP/UMask0077/Delegate=noを維持する。
旧normal/seed-loss/reservation/full/smoke入力・証拠を保持し、旧seed-loss1537項目treeと予約拒否証拠の不変も確認する。
全input/外部runtime/owner/mode/UID read可/write不可境界、venv/AES/xattr、旧証拠、未使用unit/出力/UID/KVM/容量の最終監査後に単発開始する。
観測違反/失敗/期限超過は当該unitだけ回収し部分証拠保持、暗黙retryなし。
GCはobserver terminal unknownとして保持し、同Invocation exit recorder/trusted journal/最終cgroup・UID・port回収を別に確認する。

## 残るgate

HTTP sidecar、外部到達拒否positive control、forced delivery race、全route/正式モデル比較は別gateのまま。
旧seed-loss001の失敗原本と予約拒否の独立追加証拠は変更しない。

## 固定準備結果とcommand

[1307入力snapshot](LINUX_X86_RUNTIME_PRESENCE_SNAPSHOT_001.json)、[専用UID検査](LINUX_X86_RUNTIME_PRESENCE_PREPARATION_001.json) を保存。
source3741d15、tree SHAeb2a12e122559eb18dd993d0005d25f60de8410d1c2ee17a49de51ff843b4f7c。
作成45883とUID検査99963は同handle終端exit0。Linux全92Python＋bootstrap13成功。
root/inputs0750、全file owner/mode/hash/read可write不可、venv prefix/version/AES/help/xattr/0700work、新runs/exit/log不在を確認。
unit not-found/inactive/Invocation空、UID999 processなし、KVM root:kvm0660、free37008715776 bytes。
旧seed-loss全1537treeと予約拒否の証拠hash、旧normal/full/smoke/build archiveを準備時照合した。実行直前に再確認する。

先行observer:

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-runtime-presence-001/inputs/repo/integration/runtime_normal_observe.py --trial presence --output /tmp/tempest-runtime-presence-observation-001.jsonl
```

続く固定callerは `python3 -I -B docs/evidence/runtime-presence-001/run_once.py`。
[service](../integration/tempest-izanagi-runtime-presence-001.service) と [caller COMMAND](evidence/runtime-presence-001/run_once.py) の一致/verify成功、unitはinstall/enableしていない。
上記command/snapshotの最終監査後に一度だけ実行する。現在はobserver/callerとも未実行。

## 実行保留: aggregate計画の事前接続

room16644でaggregate::generate_innerがruns/aggregate-plan.jsonと各resultのverified comparison bindingを要求するのに、v1 runner/scriptには計画生成と--comparison-plan/slot接続がないことを確認した。
既存1307inputとv1 metadataは未実行原本として保持する。runnerはinterface提示まで変更しない。
修正版は実行前に4slot計画を固定し、aggregate selection committed4/unavailable0/unplanned0も要求する。portfolio件数だけでは欠測を合格にしない。
posthoc計画作成は行わず、新closure/計画/最終監査が揃うまでobserver/caller/VMを開始しない。

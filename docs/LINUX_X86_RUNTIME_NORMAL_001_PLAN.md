# Linux x86 runtime normal001 計画

## 範囲と状態

固定snapshotと専用UID検査は完了。room16601の監査後、実行直前検査へ進む。
#13/#14/#15 に関連する正式runtimeの mock正常2回/reset を先に検査する。
seed適用後応答喪失、finding/retest4presence はこのtrialに混ぜず後続の具体計画とする。

root /var/lib/tempest-izanagi-runtime-normal-001、unit tempest-izanagi-runtime-normal-001.service を予約する。
host tempest は build001 の SHA4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f。
Izanagi CLI/image/build-inputs は smoke002 と同じ固定実体をコピーする。
image SHA5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e、CLI SHA088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8。

## 実行内容

[固定runner](evidence/runtime-normal-001/run_normal.py) を inputs/run_normal.py として配置する。
既存 integration/runtime_smoke.py の run_once を normal-1/normal-2 に対し順に実行し、その関数の正式検査を全て維持する。
既存 main の追加 boundary-denials はこのtrialでは実行しない。
各normalはprimary/retestを持つため、合計4つのVM namespace/credentialの非再利用と固定imageを検査する。
self-check/retest、finding、control/request integrity、再送失敗なし、API2行、artifact inventory、正常cleanup、transient material不在も既存run_onceで要求する。
mockは正式なモデル比較には含めない。

## 固定入力と依存

新private HOME/tmp/runs/evidence をUID999専用に作成する。runsはrunnerが新規作成する。
新root venvを既存hash固定wheelからoffline構築し、Python -I -B と env-iを使用する。
repo/integration/runtime_smoke.py、mock-s3-overread-reset.json、scenarios/s3-overread-001.yaml、image/host_bridge.py と transport.py およびscenario参照の全closureを固定する。
source/runtime closure、全file SHA/mode/owner、外部runtime hashesをsnapshotに記録し、UID999 read可/write不可とprefix/import/crypto/--helpを検査する。
旧full/smoke/offline/build入力と証拠は不変更。image/core/global設定の変更は行わない。

## observer と回収

旧smoke observerの単一PID固定は使わない。4つのstageに対応する新observer条件を別監査する。
同時QEMU最大1、固定image snapshot=on、restrict=on/loopback agent port、各stage sandboxのreadonly mapped-xattr shareを要求する。
各QEMU PID/starttime/cwdとrun/stage/sessionを結び付け、同stage内identity交代と予期しないstage/pathを拒否する。
正常stage切替と不正な置換を区別し、観測欠測は未証明として残す。
unitのGCをobserver成功へ補完せず、同Invocation exit recorder/trusted journal/最終cgroup/UID/port回収を別確認する。

Typeexec/User999/Group988/kvm993、KillModecontrol-group、RuntimeMaxSec1800/Stop10、Restartno/UMask0077/NNP/Delegate=noを維持する。
observerと固定callerの実command・snapshot・preflightのレビュー後に単発開始する。
途中失敗/timeout/観測不確実なら当該unit停止回収、部分証拠保持、別runへの暗黙retryなし。
原本はprivate、公開は選別結果/hash。model/実credential/AWSは使わない。

## 残るgate

seed応答喪失後のdiscard、4presence、HTTP sidecar、外部到達拒否positive control、forced delivery race、全route、正式モデル比較は未証明のまま維持する。

## 正確な stage path と caller

run_cli.rs の primary は Vm::boot(&root)、retest は root/retest、vm.rs は directory/sandbox を使う。
固定shareは work/runs/normal-1/sandbox、normal-1/retest/sandbox、normal-2/sandbox、normal-2/retest/sandbox の順である。
[review用service](../integration/tempest-izanagi-runtime-normal-001.service) と [固定caller](evidence/runtime-normal-001/run_once.py) を用意した。
unitのinstall/enable/startは行っていない。runtime_envは空環境からPATH/TZ/LANG/LC_ALL/HOME/TMPDIRだけを渡す。

## 準備結果

[全1307入力](LINUX_X86_RUNTIME_NORMAL_SNAPSHOT_001.json) と [専用UID検査](LINUX_X86_RUNTIME_NORMAL_PREPARATION_001.json) を保存した。
observer/bootstrapは5445a29を取り込み、Python全82件とbootstrap13件がLinuxで成功した。
作成caller63300とUID検査55144はそれぞれ同handle終端exit0。
最初にUID999からprivate repository内helperを直接実行した試行はEACCESで起動できず、repoの権限を緩めず同一helperを/tmpへコピーして実施した。
全入力 read可/write不可、外部runtime SHA、root所有/mode、venv prefix/version/AES、--help、xattr、private workを検査した。
unitはnot-found/inactive/Invocation空、検査終了後UID999残留なし、KVM root:kvm0660、boot30389abc-903c-40ae-89a5-c6268ec1c432、free41702170624 bytes。
新target binaryも記録SHAへ照合済み。snapshot treeは07260c16884c1c48d6396a6bea1616686078876c64bad0c18a2746afbe491af5。

先行observerの具体command:

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-runtime-normal-001/inputs/repo/integration/runtime_normal_observe.py --output /tmp/tempest-runtime-normal-observation-001.jsonl
```

続く固定callerは `python3 -I -B docs/evidence/runtime-normal-001/run_once.py`。command listは同fileに固定されている。
observer JSONL の sample と observed_sessions は [projection](evidence/runtime-normal-001/observer_projection.py) で区別する。
GC/terminal未知はそのまま残し、caller/exit recorder/trusted journalと独立回収結果を別保存する。
この準備時点ではcaller/observerとも未実行で、4VM trialは未起動。

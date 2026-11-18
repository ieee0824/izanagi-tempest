# Linux x86大容量配送control001案

## 後続の準備結果

room16838監査後、prepare42858とUID check17638は各同handleで終了コード0。
[実snapshot](LINUX_X86_DELIVERY_RACE_LARGE_SNAPSHOT_001.json)は1311項目、canonical tree `2354bff963ee837ef2de59cf927828ecd3242a0cead6ae59b12bc489613a9308`。
[準備検査結果](LINUX_X86_DELIVERY_RACE_LARGE_PREPARATION_001.json)へhash/owner-mode/read可write不可、固定Python/AES/runtime-help/CLI-help/xattr/artifact bindingと出力不在を保存した。
181 directoryはroot:988/0750、work/home/tmp/evidenceは999:988/0700。copy後free10239275008 bytesで8GiB条件を満たす。
20固定source/data・外部runtime・前段入力と保持証拠は不変。RAW cleanup provenanceも新inputへ束縛した。
新root/snapshotだけを作成し、run_once・VMは未実行。以下の「未作成」は草案時点を表す。

## 事前期待値と状態

room16830/16834に従い、`--expect completed --large-evidence`を実行前の期待値として固定する。
新root・snapshot・VMは未作成で、試験は未実施。[completed001](LINUX_X86_DELIVERY_RACE_COMPLETED_001.md)はroom16834で監査受入済み。
録画不完全・collection失敗・abortedとなった場合はこの期待値に対する失敗としてpartialを保持し、同runを後から`collected`期待へ変更しない。

固定driver `integration/runtime_delivery_race.py`はlarge flag時にscenario ID `delivery-large-001`を生成する。
local LWSのlarge-data/dummy（bodyはAを1048576文字）へGetObjectを許可し、guestの1回のsandbox_exec内でcurlを29回実行する。
budgetはmax_calls=1/timeout120s、mockのfinal findingsは空。large専用scenarioにはexpected_findingとretestを設定しないため、このcontrolは新primary 1 VMだけである。
small completed001のfresh retest検証とは別の対象であり、正式モデル比較には含めない。

## 固定資源と容量

root/unitは`/var/lib/tempest-izanagi-delivery-race-large-001` / `tempest-izanagi-delivery-race-large-001.service`。
fixture image SHAは`4c2a101c929547c422ce5f7709e4d52db69dbc2032bb7408fc4a4ce16aefe236`、host Tempest CLIは`4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f`、Izanagi CLIは`088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8`を再利用する。
旧CLIのbuild provenanceをコピーし、現HEADで再buildしたとは扱わない。guest metadataと同imageのnative artifact reportも固定する。

前段後のfree10357170176 bytesではcopy前10GiB/後8GiB条件に不足するため、room16834の許可で[限定RAW cleanup](LINUX_X86_DELIVERY_RACE_RAW_CLEANUP_001.json)を実施した。
削除は新buildのoffline派生disk.rawだけ。4GiB/SHA418897f3…、regular/singlelink/UID999:GID988/0600、実parent chainとparent FD、UID空を確認した。
93694は同handle終端0、保持対象42fileとbuild29入力のSHAは前後不変。qcow2・partition・抽出artifacts・各元RESULTは保持し、元OFFLINE/RESULTの歴史的記録は変更しない。
freeは12348448768 bytesへ増加した。

largeもcopy前10GiB以上/後8GiB以上とする。image2048524288 bytes＋CLI約10.7MB＋Python/sourceをコピーした後、約10.2GBを見込む。
同時VMは1台、一時snapshot overlay最大4GiB相当＋logs/evidence約1GiB（PCAP上限64MiBを含む）の仮枠を置く。測定済みpeakの保証ではない。
条件を満たさなければ停止し、追加削除・自動再試行はしない。

## SnapshotとUID検査

[prepare_snapshot.py](evidence/delivery-race-large-001/prepare_snapshot.py)は[固定source/data](LINUX_X86_DELIVERY_RACE_LARGE_SOURCE_001.json)、旧証拠/前2trial入力、限定RAW cleanupの正確な対象と不在・保持file SHA、image/CLI、KVM、UID999空、未使用unit/出力不在を検査してから新rootを作る。
新inputsはroot:988/dir0750/file0440（実行file0550）、work/home/tmp/evidenceは999:988/0700。固定hash wheelをoffline/no-indexで新venvへ導入する。
RAW cleanup provenanceも新inputへコピーし、原本保持の例外を黙って全旧tree不変とは扱わない。

監査後、rootの`/usr/bin/python3 -I -B docs/evidence/delivery-race-large-001/prepare_snapshot.py`でsnapshotだけを作り、[UID検査](evidence/delivery-race-large-001/check_preparation.py)をstdinで`runuser -u tempest-kvm -- /usr/bin/python3 -I -B -`へ渡す。
全input hash/read可write不可/owner-mode、外部runtime、固定Python/AESGCM、runtime driver help/host CLI help、xattrとnative artifact binding、出力不在を検査する。この段階でVMは起動しない。
large scenarioは固定driverが実行時に生成するため、前段のs3-overread YAMLのvalidateをlarge scenario検証の代用にはしない。実runでの生成入力とplan/control/receiptの対応を別collectorで確認する。

## Callerとobserver

具体argvは[run_once.py](evidence/delivery-race-large-001/run_once.py)のCOMMANDを正とする。
Type=exec、UID/GID tempest-kvm・補助kvm、RuntimeMaxSec1800/TimeoutStopSec10、KillMode=control-group、SendSIGKILL=yes、Restart=no、UMask0077、NoNewPrivileges=yes、Delegate=no、専用cwd/env-i/ExecStopPostを維持する。
内側のfixed driverは`--expect completed --large-evidence`、固定tempest/izanagi/image/image-inputs/python/runsを使い、host run subprocessのtimeout720秒とunit期限を区別する。

```sh
NEW_ROOT=/var/lib/tempest-izanagi-delivery-race-large-001
# snapshot/UID結果の監査後にだけ、固定observerを先行する。
sudo -n /usr/bin/python3 -I -B "$NEW_ROOT/inputs/repo/integration/runtime_normal_observe.py" \
  --trial delivery-race-large \
  --output /tmp/tempest-delivery-race-large-observation-001.jsonl
# 別handleで一度だけ実行する。
python3 -I -B docs/evidence/delivery-race-large-001/run_once.py
```

observerの新profileは`work/runs/forced-delivery-race/sandbox`の1 stageだけを許可する。
restrict/snapshot/readonly-share、単一QEMU/PID-starttime/cwd、boot nonce/session fingerprint、stage順序・入替拒否は既存validatorを維持する。既存14テストは成功した。
GC終端unknownは独立trusted終了と分け、collectorが固定validatorのreplayと1 stage/bindingの完備性を確認する。

## 受入と保存

run.status=completed、primary export started1回、同host audit IDのexecution_errorから認証済み回復、forced_reader_pidのmoved包含、正のfreeze時間、export.complete/manifest.complete/collection.completeを要求する。
API evidence29行・PCAPが56〜64MiB、3 export fileの実長/SHAと全collection receipt、生成large scenario/1 agent call/未設定retest、formal_metrics_eligible=falseを照合する。
primaryの正常cleanup、artifact inventory complete、transport key不在、same-Invocation trusted終了、UID/cgroup/観測port回収と全固定入力・保持証拠の不変を保存する。
host audit IDとnative mailbox export IDは区別する。caller/observerの同handleを終端まで追い、元run・失敗partialを保存して自動retryしない。
成功しても敵対的な全証跡量のfreeze上限、Internet全般、本番B/MCP、実モデル比較へ一般化しない。

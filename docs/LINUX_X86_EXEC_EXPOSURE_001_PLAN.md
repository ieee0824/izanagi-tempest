# Linux x86 exec-exposure001 計画

## 範囲と状態

草案、snapshot/VM未実施。#13のexec応答・失敗診断の目印検査を既存固定image上の1VMで測定する。
root /var/lib/tempest-izanagi-exec-exposure-001、unit tempest-izanagi-exec-exposure-001.service。
Izanagi CLI SHA088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8、full003 image SHA5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7eを維持。
image/core/guest/global設定の変更や新image buildは行わない。dummyのみ、実model/credential/AWSは使わない。

## 測定対象

実装担当のimage_smoke.py opt-in --exec-evidenceを使い、execute()全呼出のstdout/stderrとtimeout部分出力を新output内0700dir/0600fileへ保存する。
返却前と最終時の両方で、既知dummy controller token、reply AES key、private payload目印をscanする。
claim/seed/probe/export等の成功と既存expected-error経路を実行し、漏出時は失敗として停止・証拠保持する。
公開は件数・operation/expected_error・leak有無と原本file hashに限定し、raw/marker値はprivateに保持する。

events/alerts rotations/up stdout/stderrの既存scanとは別の証拠とする。
これはnative root subprocess PIPE内部や全/proc cmdline観測、全route/全lifetimeの証明ではない。
既存M3 boundary/probe/API/PCAP/実eBPF nonce検査も維持し、captureをdummy eventで代替しない。
root-only agent/eBPFへのactor EACCES、HTTP実体hash、offline image binding、実agent attest hashは既存契約のまま。
--tempest/forced delivery raceは指定しない。

## 固定・監視・単発実行

新root-owned read-only input closureへimage/CLI/manifest/offline report、更新smoke/evidence helper、observer/bootstrap/transport/trace/artifact helperを固定する。
既存hash固定wheel由来の新prefix venvをoffline構築し、UID999/Group988/kvm993専用work0700、env-i/Python-I-Bで実行する。
全hash/mode/owner/外部runtime、UID read可/write不可、prefix/AES/xattr、未使用unit/出力/UID/KVM/容量と旧証拠不変を監査する。

observerはimage_smoke_observe.py --attempt exec-exposure-001。
固定unit/root/image/work/output/workspace、単一QEMU PID/starttime/cwd、snapshot/read-only mapped share/restrict usernet/loopbackを要求し、他runのimage/share/同stage VM置換は拒否する。
Typeexec/KillModecontrol-group/RuntimeMax1800/Stop10/Restartno/UMask0077/NNP/Delegate=no。
新dummy transport keyはrunごとに生成。実行helper/interfaceとsnapshot/commandの監査後に一度だけ起動する。
違反/失敗/timeoutは当該unitだけ回収し部分証拠保持、暗黙retryや権限緩和はしない。
caller/observer各実終端、同Invocation exit recorder/trusted journal、cgroup/UID/port回収と入力不変を別に確認する。
GCはobserver terminal unknownとして保持する。

## 保持と残るgate

旧presence v1/v2/results/事前plan、normal/seed-loss/reservation/full/smokeの入力・証拠を保持する。
結果監査後に当該dummy transport keyだけを値/hash非公開で削除する。
/proc cmdline全期間、native PIPE、HTTP sidecar、外部positive control、全route/正式比較は別gateとして残す。

## 可逆準備の草案

[service](../integration/tempest-izanagi-exec-exposure-001.service)、[caller](evidence/exec-exposure-001/run_once.py)、[入力作成](evidence/exec-exposure-001/prepare_snapshot.py)、[UID検査](evidence/exec-exposure-001/check_preparation.py) を用意した。
現callerはboolean --exec-evidence/保存先output内固定を想定する。実装担当のinterface/helper filenameを確認後に確定し、closureへ必要moduleを追加する。
prepareは--exec-evidence未実装時にroot作成前に停止する。まだ実行していない。
source/helper構文・service verify・ExecStart一致は成功。旧presence v1/v2/result/plan・normal・seed-loss全tree・予約拒否・full/smoke証拠hashを準備時照合する。

# Linux x86 proc-exposure002 固定準備計画

## 状態と担当

単発callerはVM前のhelper xattr設定で失敗した。[結果](LINUX_X86_PROC_EXPOSURE_002.md)を参照。以下は実施前の固定計画・準備記録として保持する。

[ページ観測設計](LINUX_X86_PROC_EXPOSURE_002_DESIGN.md)に基づく準備計画。helper/scriptとsynthetic試験はcoder、専用root/unit/observer/closure/結果回収はpronniaが担当する。
実装interfaceとsource監査前のため、snapshot・専用root作成・VM起動は未実施。
[001の失敗結果](LINUX_X86_PROC_EXPOSURE_001.md)と全固定入力・private rawを保持し、再開や遡及合格はしない。

## 新環境と固定範囲

新rootは /var/lib/tempest-izanagi-proc-exposure-002、unitは tempest-izanagi-proc-exposure-002.service、observer profileは proc-exposure-002。
固定full003 image・Izanagi CLI・offline artifact reportと既存exec/trace/rotation検査を維持し、dummyだけを使用する。
helperは秘密を含まないpublic sourceとして起動前read-only領域へ配置し、guestから見たpath/owner/modeとshareのread-onlyを確認する。
新closureにhelper/runner/observer/recorderと必要な全依存を含め、source commitと実bytesのhashをroot作成前に検証する。
001の入力数を流用せず、実際の002 snapshot件数・canonical treeを記録する。
専用UID999:GID988/kvm993、root/inputs0750、入力0440/実行0550、work0700、env-i/Python-I-B、既存hash固定wheelからのoffline venvを維持する。

## ページ観測の確認点

guest guard後の4096PID上限列挙を時点ごとに行い、最大127対象＋観測自身1PIDを1ページとする。
最大33ページ＋列挙1、blob8192B/各応答128KiB/時点合計34×128KiBを超えたら失敗する。
列挙の観測process自身は終了後に別ページから見ると消滅し得るため、役割を区別してcoverage照合から黙って除外しない。
各requested PID/starttimeに対してread/denied/vanished/reused/unstableを区別し、欠落・重複・想定外recordを拒否する。
各ページの自身recordとcontrols3種を、列挙対象recordとは別の役割として照合する。
cmdline source全文をargvに入れず、固定public helper path＋公開canary、envは公開controlとページ対象だけとする。
列挙応答・全ページのmarker scan/private保存、時点ごとの列挙開始から最終ページ終了までの期間・件数を保持する。
FD内容は読まない。ページ間の新規process・短命process・全期間/同時刻の網羅を主張しない。

## 開始前と回収

source/CLI interface確定後に固定observer負例、4096/4097境界・129以上coverage・消滅/再利用・control/切詰め/欠落/重複/総量超過のsynthetic試験を確認する。
host上でhelperのmainや実/proc採取を行わない。UID検査は固定入力read可write不可、venv/AES/help/xattr等に限る。
全hash/owner/mode・旧証拠不変・001鍵の監査状態・未使用unit/output・UID残留なし・KVM/容量を照合する。
具体argv・snapshot・新unit/profileをroomで照合した後、先行observerとfixedcallerで1VMだけ起動する。
異常時は当該unitだけ回収し部分証拠保持、暗黙retryや上限緩和はしない。
caller/observerの同handle終端と同Invocation exit recorder/trusted journalを分けて保存し、unknownはunknownのままにする。
input/旧証拠不変、cgroup/UID/port回収を確認し、安全なcounts/controls/coverageと検査scopeだけ公開する。
001当該dummy keyの回収は結果監査後の別追補とし、rawや入力を削除しない。

## 固定準備の草案

[service](../integration/tempest-izanagi-proc-exposure-002.service)、[caller](evidence/proc-exposure-002/run_once.py)、[snapshot作成](evidence/proc-exposure-002/prepare_snapshot.py)、[UID検査](evidence/proc-exposure-002/check_preparation.py)を用意した。
PR57のhelper2種とローカル拡張を保持したsmokeの実bytes hashをroot作成前に要求し、proc_paging.pyを必須closureへ追加する。
旧proc001の入力と選別RESULT参照fileもroot作成前に不変照合する。旧exec001鍵削除追補と原本の検査も維持する。
caller/serviceのExecStart完全一致、service verify、Python構文を確認した。Linux全122tests成功。
まだ新root/snapshot/UID検査/caller/observer/VMは未実施。

## 固定準備結果

[1309入力snapshot](LINUX_X86_PROC_EXPOSURE_SNAPSHOT_002.json)と[専用UID検査結果](LINUX_X86_PROC_EXPOSURE_PREPARATION_002.json)を保存した。
source d4fd5cbc7189a8f522b84d68ddc1f10e292324f0、canonical tree b251ee2441c2506d1357c51db0dffcc8c0a0cb3d74b7f6af8d8373bd9fe15c41。
prepare83950とUID検査48000は同handle終端exit0。初回のrepo絶対path指定は親directoryのEACCESでscript未実行/exit2となり、権限を変更せず同じsourceをstdinで渡して検査した。
全input hash/owner/mode/nonwrite、外部runtime、新venv prefix/依存/AES/help/xattr/private work、新output/exit/log不在を確認した。
helpはargparse終了だけで、host実/procを採取していない。Linux122testsとbootstrap13tests成功。
unit not-found/inactive/Invocation空、UID999なし、cgroupなし、KVM root:kvm0660、空き30020497408 bytesを確認した。
準備時に旧proc001/exec/presence/normal/seed-loss全tree/reservation/full/smoke証拠不変を照合し、実行直前にも再確認する。

最終監査後の先行observerは以下を予定する。

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-proc-exposure-002/inputs/repo/integration/image_smoke_observe.py --attempt proc-exposure-002 --output /tmp/tempest-proc-exposure-observation-002.jsonl
```

続くfixed callerは `python3 -I -B docs/evidence/proc-exposure-002/run_once.py`。
現時点ではsnapshotとUID検査だけで、observer/caller/VMは未実施。

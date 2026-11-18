# Linux x86 proc-exposure002 固定準備計画

## 状態と担当

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

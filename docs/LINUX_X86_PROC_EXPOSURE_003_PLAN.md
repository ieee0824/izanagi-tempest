# Linux x86 proc-exposure003 固定準備計画

## 状態と旧試験の保持

PR58のxattr設定順序修正を使用する別試験。新root /var/lib/tempest-izanagi-proc-exposure-003、unit tempest-izanagi-proc-exposure-003.service、observer profile proc-exposure-003。
まだroot/snapshot/UID検査/caller/observer/VMは未実施。source監査後にだけ固定準備へ進む。
[001のPID集合上限失敗](LINUX_X86_PROC_EXPOSURE_001.md)と[002のVM前配置失敗](LINUX_X86_PROC_EXPOSURE_002.md)の固定入力・原本・歴史的判定を保持する。001collector終端unknownを再実行で埋めない。

## 観測と固定source

[ページ観測設計](LINUX_X86_PROC_EXPOSURE_002_DESIGN.md)のguest guard・4096対象上限・127対象＋自身1PID/ページ・最大33ページを維持する。
各blob8192B/応答128KiB/時点合計34×128KiB、切詰め・error・欠落/重複・control不成立を失敗とする。
claim前・seed後・export前の3時点で列挙から全ページ完了までの期間・requested identity coverage/消滅/再利用を保存する。
ページごとの自身controlを列挙対象とは別役割で照合する。FDは一覧だけで、短命process・ページ間の新規process・同時刻/全期間の網羅は証明しない。

PR58 sourceはmapped_metadata→host chmod0444の順とし、公開helper2fileを起動前に配置する。
Linux非rootで実xattr setup regressionを含む全123tests/skip0を確認済み。UID999最小再現も002記録に保持する。
配置成功だけをproc観測成功とは呼ばない。実guestでのread-only share/metadata、各ページcontrols/marker scanは別に検証する。
固定full003 image/CLI/offline artifact reportと既存artifact/trace/rotation/exec検査を維持し、dummyのみ使用する。実model/credential/AWSは使用しない。

## 専用環境と準備

[service](../integration/tempest-izanagi-proc-exposure-003.service)、[caller](evidence/proc-exposure-003/run_once.py)、[snapshot作成](evidence/proc-exposure-003/prepare_snapshot.py)、[UID検査](evidence/proc-exposure-003/check_preparation.py)を用意した。
修正smokeとhelper2種の実bytes SHAをroot作成前にassertし、proc_paging.pyも必須closureへ含める。
旧proc001/002入力・RESULT参照file・鍵削除追補不在をroot作成前に照合する。旧exec/presence/normal/seed-loss全tree/reservation/full/smoke保全も維持する。
専用UID999:GID988/kvm993、root/inputs0750、file0440/executable0550、work0700、env-i/Python-I-B、既存hash固定wheelのoffline venvを維持する。
caller/service ExecStart一致・service verify・Python構文を確認、専用observer負例を含む21tests成功。
UID検査はread可write不可/全hash/owner/mode/venv/AES/help/xattr/privateworkに限り、host上のhelper実proc採取は行わない。

## 単発開始と回収

source監査→新snapshot/UID検査→実件数/tree/source/具体argv監査→直前入力旧証拠不変・未使用unit/output/UIDなし/KVM/容量照合の順で進む。
先行observerは固定inputsのimage_smoke_observe.py --attempt proc-exposure-003 --output /tmp/tempest-proc-exposure-observation-003.jsonl。
続くcallerは python3 -I -B docs/evidence/proc-exposure-003/run_once.py。--exec-evidence --proc-evidenceとoffline artifact reportを固定する。
1VM単発、暗黙retryなし。失敗時は当該unitだけ回収し部分証拠保持、原本や上限を変更しない。
caller/observer同handle終端、同Invocation exit recorder/trusted journal、cgroup/UID/port回収と全入力・旧証拠不変を別々に記録し、observer GCなどのunknownを成功へ変えない。
raw/目印はprivate、公開は安全なcounts/controls/coverageとmetadata・scopeだけ。collectorがmarker再取得再scanしない場合は明記する。
当該dummy keyは結果監査後に正確path/lstatを照合して別追補で回収し、値/単体hashを公開しない。
HTTP sidecar/外部positive control/forced delivery race/全route/正式モデル比較は別gateのまま。

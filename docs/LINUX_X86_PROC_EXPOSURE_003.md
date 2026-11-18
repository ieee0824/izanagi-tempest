# Linux x86 proc-exposure003 結果

[固定計画](LINUX_X86_PROC_EXPOSURE_003_PLAN.md)による単発VM試験はcaller16600同handle終端exit0、summary collected_requires_review。
[選別結果](LINUX_X86_PROC_EXPOSURE_003_RESULT.json)と[collector](evidence/proc-exposure-003/collect_result.py)を保存した。
旧001のPID上限失敗、002のVM前xattr配置失敗と各原本は保持し、追加VMや暗黙retryは行っていない。

## 3時点のページ観測

|時点|列挙対象|ページ|対象coverage|matched|vanished|全record|
|---|---:|---:|---:|---:|---:|---:|
|claim前|132|2|132|130|2|134|
|seed後|113|1|113|111|2|114|
|export前|116|1|116|114|2|117|

3時点ともpassed、全ページでcmdline/environ/FD一覧のpositive controlsが成立し、切詰め・予期しないerrorは0。
全record件数はページごとの観測自身を含む。vanishedをmatchedや読取成功へ読み替えない。
wire bytesは順に42112/35109/36562。各応答128KiB・各blob8192B・有限ページ/総量上限を維持した。
collectorはprivate保存の列挙3frame/観測4pageを固定helperの純粋summary関数で再計算し、保存summaryと完全一致を確認した。
hostでhelper mainや実/proc採取は行わない。ページ間は同時刻ではなく、列挙後の新規process・短命native・FD内容・全期間を網羅しない。

## exec保存検査と既存検査

180実行/360streamの保存exec_private_markersはpassed=true/leaked_streams=[]。
operationはexec125/ping8/claim3/attest2/seed27/probe4/seal2/export4/fetch5、expected_error_reads5、host timed_out0。
operation件数はdeliver読取を含み、新規操作数やseed再送数を意味しない。timeout部分出力はunit fixtureだけで実VM発生は確認していない。
540fileのmetadata連番・operation・error/timeout/returncode・stream名/byte数/欠落/余分fileと集計を照合し、通常単link/UID999:GID988/0600・dir0700を検証した。
目印を再取得してraw streamを再scanしていない。保存中scan結果の整合検査と、保存proc frameのsummary再計算を区別する。
既存host log marker scan・実eBPF trace probe・実agent build binding・artifact/recording境界もpassed。
raw/目印/stream hash一覧を公開せず、安全な集計と終了・不変metadataだけを保存した。

## 終了と回収

Invocation42b4754bbf1f48159eace8e9834f033a、currentboot30389abc903c40ae89a5c6268ec1c432。
observer27018は51sampleでQEMU PID302655/starttime36438214/固定workspace cwdを観測し、GCで同Invocation terminalを捕捉できず同handleexit1。
observer terminalはunknownであり、成功や全lifetime監査とはしない。
別証拠のExecStopPostは同Invocation exit0/success、trusted PID1/UID0/currentbootの開始・起動・停止を照合した。
cgroup消失、UID999残留なし、観測port35509閉鎖を確認した。
当該dummy transport keyは結果監査までprivate保持し、collectorは値/単体hashを読まない。

## collectorの試行と残るgate

初回collector13200は旧001 observer pathを参照したためQEMU identity照合でexit1。新RESULT生成前に停止し、旧RESULTは変更していない。
observer/result出力pathを003へ修正し、回収処理だけを再実行した。VMやcallerは再実行していない。
HTTP sidecar・外部positive control・forced delivery race・全route/全期間・正式モデル比較は別gateのまま。実model/credential/AWSは使用していない。

修正後collector67581は同handle終端exit0。全1309入力/外部runtime・旧proc001/002/exec/presence/normal/seed-loss全1537tree/reservation/full/smoke証拠の不変、旧鍵不在も照合した。

個別helperのguest statは実測していない。host側の通常単link/999:988/0444・source hash一致とmapped uid0/gid0/mode0100444を別に照合し、成功したguest readや共有EROFSから個別guest owner/mode実測へ一般化しない。
追補collector85104も同handle終端exit0。host helper2fileのmetadata/xattrとsource hash、既存再計算/不変検査を照合した。

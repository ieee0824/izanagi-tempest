# Linux x86 proc-exposure001 結果

[固定計画](LINUX_X86_PROC_EXPOSURE_001_PLAN.md)に従う1VM単発試験は、初回before_claimのPID集合上限超過で停止した。
[選別結果](LINUX_X86_PROC_EXPOSURE_001_RESULT.json)と[collector](evidence/proc-exposure-001/collect_result.py)を保存した。暗黙retry・上限緩和は行っていない。

## 初回snapshotと未到達範囲

actor UID1000のguest guardとcmdline/environ/FD一覧のpositive controlは3種とも成立した。
保存された128件はidentity前後が安定し、cmdline read128、environ denied127/read1、FD denied127/listed1。
stream切詰め0・予期しないerror0だが、pid_set_truncated=trueのため完全性を拒否した。
総PID数の正確な値や、採取対象外の内容は推定しない。

summaryはincomplete、proc_before_claim.passed=false。
after_seed/before_exportと最終exec_private_markers検査は未到達であり、3時点合格や全体の漏出なしを主張しない。
2実行・4stream・metadata2件をprivateに保持した。6fileは通常単link/UID999:GID988/0600、dir0700。
collectorは保存guest JSONだけから安全なsummaryを再計算し照合した。host上のproc snapshotは実行せず、目印を回収した再scanも行っていない。

## 終了と証拠保全

caller34542は同handle終端exit1、observer43580は同handle終端exit0でloaded/failedの同Invocationを捕捉した。
Invocation ec197df910a34e42b0818f2d6333feba、QEMU PID300385/starttime36179402、固定workspace cwdを26sampleで観測した。
ExecStopPostも同Invocation/exit1/exit-code、trusted PID1/UID0/currentbootの開始・起動記録を照合した。
cgroup消失、UID999残留なし、観測port34227閉鎖を確認した。これは全期間の非観測を証明しない。

全1308input・外部runtimeと旧exec/presence/normal/reservation/full/smoke証拠、seed-loss全1537treeの不変をcollectorで照合した。
collectorの選別RESULT生成は確認したが、元collector呼出しの終端exit値は回収できていないためunknownを保持する。
当該dummy transport keyは失敗結果監査までprivateに保持し、値/単体hashを読んでいない。

## 次の検討

room16691でcoderが有限ページ数・総bytes上限を持つPID集合のページ分割方式を具体化中。
次試験は別root/profile/入力の計画として監査し、001の固定入力や結果を上書きしない。
FD内容・短命native process・全期間/全route・HTTP sidecar・外部positive control・forced delivery race・正式モデル比較は未証明のまま。

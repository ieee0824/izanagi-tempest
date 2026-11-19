# Linux x86 runtime reservation001 結果

## 独立した予約拒否証拠

[計画](LINUX_X86_RUNTIME_RESERVATION_001_PLAN.md) の単発追加検査は成功した。
実CLIはexit1、stdout JSONはscope=m5_evaluation/runs=[]/stopped=infrastructure:...EEXIST。
PR48のtyped判定と保存witnessが一致し、check/caller17735は同handle終端exit0だった。
[選別結果](LINUX_X86_RUNTIME_RESERVATION_001_RESULT.json) と [collector](evidence/runtime-reservation-001/collect_result.py) を保存した。
stdout/stderr原本は新private evidenceへ保存し公開しない。

旧seed-loss001全tree1537項目はbefore/after SHA256が4f96c6013ae88321ab3376a636092b962c924d39e52ae1b7dd700a620b70f878で一致。
通常file内容、owner/mode、inode/device/link、mtime/ctime、symlink target、xattr hashを比較した。atimeは読取で変わるため除外した。
旧run/inputs/証拠を変更せず、一度だけ既存IDの拒否を検査した。新VMやseed再送は行っていない。
旧seed-loss trial自体の失敗判定と旧retry出力欠測は保持する。この追加証拠で遡及合格にはしない。

## 独立監視・終了

最終preflight70362は同handle終端exit0。observer4468先行後、固定caller17735を一度実行した。
observerの59サンプルでhost/unit QEMUは非観測。事後もQEMU/UID999なし、専用cgroup消失。
固定build元sourceではexclusive reservationがVM bootより前であることも別に確認した。
sampling間の完全な不存在証明とは呼ばない。

observer4468は最終unit GCでsame-invocation terminal unknown、同handle終端exit1。
別証拠としてExecStopPostの同Invocation67f4f9378e49423fb349662d5ec35326/exit0/success、trusted PID1/UID0/currentbootの開始・起動・停止3イベントが一致した。
資源使用量の追加journal行はこの短時間unitでは存在せず、collectorの最初の固定4行assertは失敗した。必要なlifecycle event IDを照合する修正後、collector86316は同handle終端exit0。
collectorだけを再実行し、CLI/unitは再実行していない。
全8input/global runtimeは不変だった。正式モデル比較・実credential/AWSは使用していない。

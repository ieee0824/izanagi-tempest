# Linux x86 proc-exposure002 起動前失敗

[固定計画](LINUX_X86_PROC_EXPOSURE_002_PLAN.md)の単発callerはhelper配置でexit1となり、VM起動へ到達しなかった。
Invocation dd6e5cb56b4640ba922e548b3c984f37。暗黙retryや既存outputの再利用は行っていない。

## 原因と観測範囲

最初のpublic helperを書いた後、host chmod0444→mapped_metadataの順でLinux user xattrを設定しようとしてos.setxattrがEACCESになった。
readonly-check/proc_evidence.pyはUID999:GID988/0444で固定sourceとhash一致、次のproc-probe.pyは未作成。
summary/exec-evidenceも未作成、3時点のproc観測と最終marker scanは未到達。
helper準備はIzanagi起動より前であり、VM受入試験として数えない。

callerは即時exit1（継続sessionなし）、先行observer13879は6sampleでQEMU/listener0、同Invocation loaded/failedを捕捉後、QEMU identity未観測を拒否して同handle exit1。
これはobserver成功や全期間の不在証明とは呼ばない。
ExecStopPostも同Invocation/exit1/exit-code。cgroup消失、UID999残留なしを確認した。

## Linux専用UIDでの最小再現

room16709に従い、UID999で秘密を含まないpublic dummyfileと固定transport.mapped_metadataを使用した。
旧順序write→chmod0444→xattrはerrno13、修正候補write→xattr→chmod0444は成功。
host0444/owner非writeとmapped uid0/gid0/mode0100444を読み返して照合し、一時directoryは削除した。
VM/helper実procや秘密値を使用していない。production修正とregressionはcoderが担当する。

## 証拠と次試験

[選別結果](LINUX_X86_PROC_EXPOSURE_002_RESULT.json)と[collector](evidence/proc-exposure-002/collect_result.py)はraw/keyを公開せず、固定入力と旧証拠・終了metadataを照合する。
当該dummy transport keyは結果監査までprivateに保持し、値/単体hashを読まない。
修正版は別003 root/unit/profile/sourceとして計画し、002固定入力・原本を上書きしない。
001のPID上限失敗・collector終了unknownも維持する。

collector94576は同handle終端exit0。全1309入力・外部runtime・旧proc001/exec/presence/normal/seed-loss1537tree/reservation/full/smoke証拠不変とtrusted同Invocation開始/起動を照合した。

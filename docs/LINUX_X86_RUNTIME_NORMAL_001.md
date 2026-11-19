# Linux x86 runtime normal001 結果

## 到達範囲

[固定計画](LINUX_X86_RUNTIME_NORMAL_001_PLAN.md) の normal-1/normal-2 は両方 completed / evaluation performed。
caller49419は同handle終端exit0、予定したprimary/retestの4VMだけを逐次実行した。
[選別結果](LINUX_X86_RUNTIME_NORMAL_001_RESULT.json) と [collector](evidence/runtime-normal-001/collect_result.py) を保存した。

両runで self-check established / finding found / retest passed、control integrity と request integrity は matched、contaminated=false、failed control operations は空。
各runのmock3callsとAPI2行、artifact inventory complete、4つの異なるVM binding/ダミー資格情報を確認した。
/tmp canary のresetは既存runtime_smoke.run_onceと固定mockで検査した。
primary/retest双方のcompanion/management/down/up cleanup成功、forced group stopなし、missing logsなし。
実agentのattest SHAも固定build入力と一致した。一時transport-hmacとrun内__pycache__は残っていない。
mockはformal_metrics_eligible=falseであり、正式なモデル比較結果ではない。

## 監視・終了・回収

observer99199は4stageすべてのPID/starttime/cwdとrunning bindingを観測した。
各bindingは実run reportのboot_nonce/supervisor_pid/session_fingerprintと一致した。
最終unit GCでsame-invocation terminal attributesを捕捉できず、同handle終端exit1。terminal unknownを維持する。
interval間の完全lifetime監査やobserver成功とは呼ばない。

別証拠として、ExecStopPostはInvocation d0bf251254d64f7890690c562193c493でexit0/success。
trusted PID1/UID0/currentboot journalの4 lifecycle rowsが同unit/Invocationに一致した。
cgroup消失、UID999残留なし、観測4port閉鎖、全1307input/global runtime/旧full001002003証拠/旧smoke001v1v2と002入力不変を確認した。
collector8114は同handle終端exit0。追加stop/kill/暗黙retryは不要だった。

## 残るgate

この結果は正常mock2回/resetの範囲。seed適用後応答喪失→discard、4presence、HTTP sidecar、外部到達拒否positive control、forced delivery race、全route、正式モデル比較を証明しない。
実model/実credential/AWSは使用していない。原本run/API/PCAP/logはprivateに保持する。

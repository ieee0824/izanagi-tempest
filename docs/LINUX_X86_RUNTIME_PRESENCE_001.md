# Linux x86 runtime presence001 結果

## 4presenceと集計

[固定v2計画](LINUX_X86_RUNTIME_PRESENCE_001_PLAN.md) を一度実行し、4runすべてcompleted / evaluation performed。
caller66146は同handle終端exit0、予定した6VMだけを逐次実行した。
[選別結果](LINUX_X86_RUNTIME_PRESENCE_001_RESULT.json) と [collector](evidence/runtime-presence-001/collect_result.py) を保存した。

finding/retestの11→10→01→00で、primary probeはfinding有の2runで同ID開始/完了各1、無の2runで0だった。
未設定self-check/retestはperformed=false/reason=not_configured。未設定retest directoryは生成されず、設定時はchecks_passed。
findingはfound/not_configured、retestはpassed/not_performedへ正しく分かれた。

事前に固定した4slot計画と実runs/aggregate-plan.jsonはbyte-identical。
全resultのcomparison bindingはverified、期待conditions/evaluator一致、計画SHA/slot IDが一致した。
集計selectionはplanned/discovered/committed4、unavailable0/unplanned0。
portfolioはfinding/retestともconfigured_denominator2/not_configured2、cross_condition_rates=not_computed。
formal eligibleは0で、mockを正式モデル比較へ昇格していない。

## 6session・終了・回収

6つのVM binding/nonce/sessionとダミー資格情報は再利用されず、observerの全6stage bindingが実run reportに一致した。
各stageのcompanion/management/down/up cleanup成功、forced group stopなし、missing logsなし。一時transport-hmac/cacheは残っていない。
実root agentのattest SHAは固定build入力に一致し、control/request integrityはmatched、contaminated=false、artifact inventoryはcompleteだった。

observer60231は全6stage照合後、unit GCによりsame-invocation terminal attributesを捕捉できず同handle終端exit1。
terminal unknownを保持し、observer成功やサンプル間の完全lifetime監査とは呼ばない。
別証拠として、ExecStopPostはInvocation30121ae1574b4640bd5c0176d0a1bbb2/exit0/success。
trusted PID1/UID0/currentbootの開始・起動・停止イベントも同unit/Invocationに一致した。
cgroup消失、UID999残留なし、観測6port閉鎖を確認した。

全1316inputのhash/owner/mode、記録directory、global runtimeとv1原本は不変。
旧seed-loss全1537tree、予約拒否追加証拠、旧normal/full/smoke入力証拠も不変だった。
collector2615は同handle終端exit0。追加VMや暗黙retry、事後の計画変更は行っていない。

## 残るgate

HTTP sidecar、外部到達拒否positive control、forced delivery race、全route/正式モデル比較は別gateのまま。
実model/実credential/AWSは使用していない。原本run/API/PCAP/logと集計はprivateに保持する。

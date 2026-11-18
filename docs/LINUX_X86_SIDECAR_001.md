# Linux x86 sidecar001 結果

[固定計画](LINUX_X86_SIDECAR_001_PLAN.md)の1VM単発試験はcaller43001同handle終端exit0、summary collected_requires_review。
[選別結果](LINUX_X86_SIDECAR_001_RESULT.json)と[collector](evidence/sidecar-001/collect_result.py)に証拠を保存した。
restrict_network=true/read-only mapped share/固定full003 image・Izanagi/LWSを維持し、mock classifier/allow_export=falseとdummy loopbackだけを使用した。

## loopback対照とmetadata

単一guest exec内でreceiver19090/19091を起動し、19091への直接転送成功を対照とした。
proxy18080経由の19090転送は成功、別port19091はclient502/metadata policy allowed・outcome failed、非許可Hostはclient502/metadata policy denied・outcome rejected。
receiver件数[1,1]と公開nonce/body hash応答の対照が成立し、負例による追加到着はなかった。receiver threadはfinallyで回収した。
3request/completed1/private_port_failed1/host_rejected1をfresh sessionとguest boot、client socket/request ID/source/sequence/観測区間/byteへ紐付けた。
auditは1file/178439bytes。保存fixtureのbounded JSONとprivate auditから固定pure validatorで再計算して保存summaryへ完全一致を確認した。
公開dummy body markerがaudit metadataへ保存されていないことも確認した。これは秘密の独立再scanとは異なる検査である。

sidecarはguest root UID0、PID788/starttime760/ppid784、argv先頭の固定binary pathで前後一致を確認した。
全argv・親実体・実稼働exe hashは未測定。offline HTTP artifact hash/ELFと実read、host helper source/mode/xattrは別証拠であり、個別guest helper statへ一般化しない。
HTTP転送成功は外部通信・writer attribution・classifier精度の成功を意味しない。teardown後のhealth eventはidentityを照合し、request-time healthと区別する。

## exec・共通検査と未実行項目

exec13実行/26stream、expected_error_reads0/host timed_out0、保存中marker scanはpassed/leaked_streams=[]。
全39fileの通常単link/999:988/0600・dir0700、metadata連番・stream名/byte/operation集計を照合した。
host events/alerts rotations・up stdout/stderr・sidecar auditを含む保存log scanと、共通実eBPF trace probeもpassed。
collectorはmarkerを回収してraw streamを再scanせず、保存scan整合とfixture/audit純粋validator再計算を区別する。
timeout部分出力はunit fixtureのみで、今回VMのhost timeout実発生は0。
専用sidecar modeでは通常M3のseed/probe/export/API/PCAPシナリオを実行していない。以前のM3実績を今回へ混ぜない。

## 終了と保全

Invocationacbe85581f7d4f0c931cfa0de7a404d1、hostboot30389abc903c40ae89a5c6268ec1c432。
observer1201は27sampleでQEMU305527/starttime36631367/固定workspace cwdを観測し、GCで同Invocation terminalを捕捉できず同handleexit1。terminal unknownを保持する。
別証拠のExecStopPostは同Invocation exit0/success。trusted PID1/UID0/currentbootの開始・起動・停止と別に照合した。
cgroup消失、UID999残留なし、観測port36913閉鎖を確認した。
当該dummy transport keyは結果監査までprivate保持、値/単体hash非読取。raw/stream hash一覧や秘密値は公開しない。
追加VM/暗黙retryは行っていない。外部positive control・forced delivery race・全route/全期間・実認証/正式モデル比較は残gateのまま。

collector61318は同handle終端exit0。全1311入力/外部runtime・旧proc001/002/003/exec/presence/normal/seed-loss全1537tree/reservation/full/smoke原本の不変、旧鍵不在を照合した。audit保存copyは元fresh sessionのfile集合/byte hashへ照合し、owner/mode/単linkと有限byte/record/segment上限を確認した。

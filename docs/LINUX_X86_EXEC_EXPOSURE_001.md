# Linux x86 exec-exposure001 結果

## 採取と保存scan

[固定計画](LINUX_X86_EXEC_EXPOSURE_001_PLAN.md) の1VM単発試験はcaller27333同handle終端exit0、summary collected_requires_review。
[選別結果](LINUX_X86_EXEC_EXPOSURE_001_RESULT.json) と [collector](evidence/exec-exposure-001/collect_result.py) を保存した。

execute173回のstdout/stderr346streamを採取し、保存されたexec_private_markersはpassed=true/leaked_streams=[]。
operation分類はexec118、ping7、claim2、attest2、seed29、probe4、seal2、export4、fetch5。expected_error_readsは7。
これらはdeliver読取回数を含み、seed操作29回や全route網羅を意味しない。
host timed_outは0。timeout部分出力の保持・scanはunit fixtureの確認だけで、今回VMでの発生確認とは呼ばない。

collectorは173metadataの連番/operation/expected_error/timeout/returncode/2stream名・byte数を確認し、件数とoperation集計を保存summaryへ照合した。
全519fileは通常file/単一link/UID999:GID988/0600、dir0700。予定外file/欠落/size不一致はなかった。
秘密目印を再取得せず、raw streamも再scanしていない。これは実行中scanの保存結果とmetadata整合の検証であり、独立した目印再scanとは区別する。
raw/marker値はprivateに保持し、公開は安全な件数・operation/expected-error/timeout/leak有無と検査・終了metadataに限る。

## 既存検査と回収

既存events/alerts rotation/up stdout/stderrのmarker scanと実PID/path eBPF trace probeは別々にpassed。
offline artifact/read境界・実agent hash・API/PCAP境界も維持した。
observer50132は単一QEMU PID298082/starttime36069385/固定workspace cwdを観測後、GCで同Invocation terminalを捕捉できず同handle終端exit1。
terminal unknownを保持し、observer成功や全lifetime監査とは呼ばない。

別証拠としてExecStopPostはInvocation03c26871e1d941c38a4cd2a4a9470583/exit0/success。
trusted PID1/UID0/currentbootの開始・起動・停止も同unit/Invocationに一致した。
cgroup消失、UID999残留なし、観測port37431閉鎖、全1307input/global runtimeと旧presence/plan/normal/seed-loss1537tree/reservation/full/smoke証拠の不変を確認した。
collector93945は同handle終端exit0。追加VM/暗黙retryは行っていない。
当該dummy transport keyは結果監査までprivateに保持し、collectorは値を読んでいない。

## 残るgate

native root PIPE内部、全/proc cmdline、全route/全lifetime、HTTP sidecar、外部positive control、forced delivery race、正式モデル比較を証明しない。
実model/実credential/AWSは使用していない。次/proc測定を今回の固定入力や結果へ後追い追加しない。

## 結果監査後の鍵回収追補

room16678の監査後、当該output/izanagi-hmacだけをlstatでUID999:GID988/0600/通常単linkと確認して削除し、非存在を確認した。値/単体hashは読んでいない。[別追補metadata](LINUX_X86_EXEC_EXPOSURE_001_KEY_CLEANUP.json)を保存し、元RESULTの採取時点の状態とraw証拠/inputsは保持した。

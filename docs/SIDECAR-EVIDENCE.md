# 固定Linux HTTP sidecarの検証範囲

PR #60の専用modeを固定full003 imageで1VMだけ実行した。
[固定計画・結果・再現手順](https://github.com/ieee0824/izanagi-tempest/blob/5a5cbd7/docs/LINUX_X86_SIDECAR_001.md)と
[選別RESULT](https://github.com/ieee0824/izanagi-tempest/blob/5a5cbd7/docs/LINUX_X86_SIDECAR_001_RESULT.json)を保存した。
上流Izanagi `16d0b55947006a166cfa29dcb8bfe71f65f8c36a` / LWS `2c0ea463f334f10a562e54f1cdc7ba8a474029e2`、
restrict_network=true、read-only mapped share、mock classifier/allow_export=falseを維持した。実model/credential/AWSは使わない。

## 対照と観測

| 検査 | client/receiver | sidecar metadata |
|---|---|---|
| receiver19091への直接対照 | 200・公開dummy body hash応答一致 | sidecarを通さない |
| proxy18080からfixture19090 | 200・同dummy応答一致 | policy=allowed、outcome=completed、upstream/response bytes正 |
| proxyから別port19091 | 502・receiver追加到着0 | policy=allowed、outcome=failed、upstream/response bytes0 |
| proxyから非許可Host | 502・receiver追加到着0 | policy=denied、outcome=rejected、upstream/response bytes0 |

receiver件数は[1,1]、単一exec内のthread/socketをfinallyで回収した。
3requestをclient socket→request ID→outcome、fresh session/guest boot/source/sequence/有限観測区間へ結び付けた。
保存auditは1file/178439bytes。固定pure validatorによるfixture/auditの再計算結果が実行中summaryと一致した。
公開dummy body markerはmetadata auditに残っていない。終了後healthはrequest-time healthと分ける。

13exec/26streamの保存中管理目印scanは漏出0、39private fileの件数・byte・通常単link/UID999:GID988/0600・dir0700を照合した。
collectorは管理目印を回収した独立raw再scanを行わず、Mac監査は保存source/RESULTの整合確認である。
host logs/audit scan、実eBPF nonce/PID/path probe、host helper source/mode/xattrも別証拠として確認した。

## 終了・未確認項目

callerはexit0、同InvocationのExecStopPost/trusted journalもexit0/success。cgroup消失・UID999なし・観測port閉鎖と1311入力/旧証拠不変を別に確認した。
observerはGCで終端を捕捉できずexit1/unknownを保持する。これを成功や全lifetimeの観測へ読み替えない。
sidecarのargv先頭固定path・root UID・PID/starttime前後一致とppid値は記録したが、全argv・親実体・稼働exe直接hashは未測定。
個別guest helper statも未測定であり、host mapping設定とguest読取から一般化しない。

この専用modeでは通常M3のseed/probe/export/API/PCAPを実行していない。
外部egress、全writer attribution、分類精度、全期間/全route、強制競合、実認証・正式model比較は未完のまま。
#36全体の受入完了を意味しない。実行方法は[image README](../image/README.md#http-sidecar専用のloopback検査)を参照する。

# 固定Linux VM外host endpointの検証範囲

PR #62の専用modeで固定full003 imageを1VMだけ実行した。
[固定計画・結果・再現手順](https://github.com/ieee0824/izanagi-tempest/blob/31da36c/docs/LINUX_X86_HOST_ENDPOINT_001.md)と
[選別RESULT](https://github.com/ieee0824/izanagi-tempest/blob/31da36c/docs/LINUX_X86_HOST_ENDPOINT_001_RESULT.json)を保存した。
Izanagi `16d0b559` / LWS `2c0ea463`、restrict=on・snapshot・read-only mapped shareを維持し、dummyだけを使った。

## 正常対照と拒否結果

| 検査 | 実測 |
|---|---|
| host127.0.0.1:59583への前後直接対照 | 同public nonce/phaseのecho2件が成功 |
| guest自身のraw TCP loopback | 55Bのechoとthread回収が成功 |
| guestから10.0.2.2:59583 | connected=false、os_error/errno111（ECONNREFUSED） |
| guest試行前後のhost accept | 1→1、追加accept0 |
| 最後の対照・停止後 | 総accept2、phases before/after、errors0、thread終了 |

host receiverは同一bind/socket inodeを保持した。hostのcall開始終了とguest自身のmonotonic区間は分け、異なる時計を直接比較しない。
対象は当該VM外host-alias endpointだけであり、Internet全般や本番MCP/B通信の拒否を証明しない。

## 独立observerと保存証拠

receiver PID307534/starttime36855709/socket inode961810を固定unit MainPID/cgroup・PID stat前後・FD・fresh ss全owner/inodeへ独立照合した。
root:988/0440単linkのackを受けてから試行し、waiting_ready23/live1/closed2の26sampleと終了後listener不在を保存した。
QEMUのPID307544/starttime36855871/固定cwdとhostforwardはreceiverと別roleで拘束した。
保存ready/ack/closed、private host closed_state、private guest stdoutと固定pure validatorの再計算がsummaryへ一致した。
このsampling/handshakeを全期間の連続監視へ一般化しない。

13exec/26streamの保存中管理目印scanは漏出0。39private fileの連番・byte・通常単link/999:988/0600、dir0700を照合した。
collectorは目印を回収した独立raw再scanを行わず、Mac監査は保存source/RESULTの整合確認である。
共通実eBPF trace、host log scan、host helper source/mode/xattrを確認した。個別guest helper statは未測定。

callerはexit0、同InvocationのExecStopPost/trusted journalもexit0/success。cgroup消失・UID999なし・両port閉鎖、1314入力/旧証拠不変を別に確認した。
observerはGCでunit終端を取得できずexit1/unknownを維持する。receiver closedの観測とunit終端取得は別である。
通常M3のseed/probe/export/API/PCAPとsidecar fixtureはこのmodeで実行していない。
強制配送競合・全route/全期間・PIPE/FD内容、実認証・正式model比較は未完であり、#36全体の完了を意味しない。
実行契約は[image README](../image/README.md#vm外host-endpointへの接続拒否対照)を参照する。

# Linux x86 host-endpoint001 結果

[固定計画](LINUX_X86_HOST_ENDPOINT_001_PLAN.md)の1VM単発試験はcaller27035同handle終端exit0、summary collected_requires_review。
[選別結果](LINUX_X86_HOST_ENDPOINT_001_RESULT.json)と[collector](evidence/host-endpoint-001/collect_result.py)を保存した。
固定full003/Izanagi/LWS、restrict=on・snapshot・read-only mapped shareを維持し、dummyだけで試験した。追加VMや暗黙retryはない。

## 対照と接続結果

host127.0.0.1:59583へのbefore/after直接対照2件と、guest内raw TCP loopback対照が成功した。
guestから同portの10.0.2.2へ1回接続し、connected=false/os_error/errno111（ECONNREFUSED）を得た。
guest試行前後のhost accept数は1→1、最後の対照後は2。phase before→before→before,after、errors0・同bind/inode/thread aliveを確認した。
close/join後closed_stateもaccepts2/phases before,after/errors0/thread_alive=falseで、最後のsnapshotから停止までの追加到着を成功扱いしていない。
公開nonceとhost portはphase・guest結果・observer ackに結び付けた。hostのcall開始終了でguest試行を囲み、guest時計とhost時計を直接比較していない。
この結果は当該VM外host-alias endpointに限定し、Internet全般や本番MCP/B通信の拒否・正式model適格性を証明しない。

## 独立observer handshake

host receiverはcontroller PID307534/starttime36855709、socket inode961810、exact127.0.0.1:59583。
receiverのready6fieldを固定unit MainPID/cgroup・PID stat前後・FD inode・fresh ssの全owner/inodeへ独立照合してroot:988/0440単linkackを公開した。
ackのInvocationは6b9da014633343139752ed28c14e77d8。waiting_ready→live→closedのphaseを保存し、closed後のfresh listener不在を確認した。
QEMU hostforward listenerとreceiverは別role/port/PIDであり、単一QEMU/restrict/image/share/cwd検査は維持した。
保存ready/ack/closedとprivate network-hostの対応、private guest stdoutとの一致、closed_stateを含むpure validator再計算をcollectorで一致を確認した。
このsampling/handshakeを全期間の連続観測へ一般化しない。

## exec・共通検査と終了

exec13実行/26stream/39file、全operation exec、expected_error_reads0/host timed_out0。保存中marker scanはpassed/leaked_streams=[]。
metadata連番/stream名/size/count/owner/modeを照合し、通常単link/999:988/0600・dir0700を確認した。
既存host log scan（private network-hostを含む）と共通実eBPF trace probeもpassed。
marker再取得によるraw stream再scanは行わず、保存scan整合と保存host/guest対照のpure validator再計算を区別する。
通常M3のseed/probe/export/API/PCAPとsidecar fixtureは今回実行していない。
個別guest helper statや全route/PIPE/FD内容/実認証・正式モデル比較は未測定のまま。

hostboot30389abc903c40ae89a5c6268ec1c432、QEMU PID307544/starttime36855871/固定workspace cwd。
observer4610は26sampleを保存し、GCで同Invocation terminalを捕捉できず同handleexit1。receiver closed観測とunit terminal unknownは別に記録する。
別証拠のExecStopPostは同Invocation exit0/success。trusted PID1/UID0/currentbootの開始・起動・停止を照合した。
cgroup消失、UID999残留なし、観測port43569/59583閉鎖を確認した。
当該dummy transport keyは結果監査までprivate保持し、値/単体hash非読取。固定入力・旧証拠・raw原本を保持する。

collector87552は同handle終端exit0。全1314入力/外部runtime、旧sidecar/proc001/002/003/exec/presence/normal/seed-loss全1537tree/reservation/full/smoke証拠の不変と旧鍵不在を照合した。host helper2fileは通常単link/999:988/0444・source hash一致・実mapped uid0/gid0/mode0100444を確認した。

## 監査後の鍵回収追補

room16780のsource監査後、同Invocation exit0/unit終了/cgroup消失/UID999なし/port43569・59583閉鎖を再確認した。
全親path実体と当該HMACの通常単link/999:988/0600を照合して当該fileだけunlink、値/単体hash非読取で非存在を確認した。
[別追補metadata](LINUX_X86_HOST_ENDPOINT_001_KEY_CLEANUP.json)を保存し、元RESULT・固定入力・raw原本を保持する。

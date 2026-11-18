# Linux x86 image smoke002 結果

## 到達範囲

[固定計画](LINUX_X86_IMAGE_SMOKE_002_PLAN.md) の単発実行は caller exit0、summary collected_requires_review となった。
[選別結果](LINUX_X86_IMAGE_SMOKE_002_RESULT.json) を保存した。これは正式受入ではない。

- actor の agent/eBPF 読取は EACCES、HTTP の実体 hash/ELF は期待値一致。offline image binding と別に、実行中 root agent の attest hash も一致した。
- claim/seed、dummy local LWS の200/403/501、mapped-xattr UID衝突 positive control/private拒否、readonly EROFS、doas/fw_cfg/proc/cgroup/private socket/RPC境界を実行した。
- normal/timeout/abnormal の子process境界、export cgroup barrier、既知IDの反復/並行取得、dummy HTTP 2件のAPI/PCAP境界まで到達した。
- guest実PID1600の今回nonce pathを含む open event が1件一致した。events.log と rotation .1 の実採取hashを保存し、private marker検査も成功した。

## 独立監視の制限と回収

observer34738は同handle終端exit1、caller37595は同handle終端exit0。
observerは52samplesで同QEMU PID285545/starttime35315195と固定workspace cwdを観測したが、最終sampleはunit GC後のnot-found/inactive/Invocation空であり、同Invocationのterminal属性を捕捉できなかった。
監視成功へ読み替えず、terminal unknown を保持する。sample間の全lifetime完全監査を証明しない。

一方、既存ExecStopPostは同Invocation6724ab53f2dd4acfb9f9499281466071のexit0/successを保存した。
trusted PID1/UID0/currentboot journal の4 lifecycle rowsも同unit/Invocationに一致した。
cgroup消失、UID999残留なし、動的agent port44571閉鎖、全1306inputとglobal runtime/旧full001002003証拠/旧001v1v2入力不変を別途確認した。
[選別 collector](evidence/image-smoke-002/collect_result.py) は同handle85469終端exit0。
追加stop/killや再実行は行っていない。room16586 の結果監査後、当該runの独立dummy keyだけを削除し非存在を確認した。削除時は値/単体hashを読まず、ログ原本は保持した。

## 残る gate

root-only agentへのactor lddは未検証で、実起動/attest hashと区別する。
Izanagi HTTP sidecarの実起動/採取、外部到達拒否と正常positive controlの組、独立Rust MCP route、forced delivery race、二run reset/cross-run contamination、全route coverage、正式モデル比較は未証明。
今回の1PID/path eventを全syscall/ABI/時計精度の保証にしない。実AWSは使用していない。

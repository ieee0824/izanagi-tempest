# 新capture large control 001 結果

事前expect completedを維持した単発runtimeはcaller40205終端exit0。run completed/evaluation performed。observer43947は365sampleを保存したがunit GCで終端属性が欠測しexit1。このunknownをobserver成功へ読み替えず、独立trusted journalとexit recorderで同Invocationの正常終了を確認した。

固定collector57760は終端exit0。[保存結果](LINUX_X86_CAPTURE_LARGE_001_RESULT.json)、[handle/collector SHA](LINUX_X86_CAPTURE_LARGE_LIFECYCLE_001.json)、[直前検査](LINUX_X86_CAPTURE_LARGE_PREFLIGHT_001.json)を保存した。元large001失敗の期待値・結果は変更せず、同runのretryは行っていない。

## 録画と配送

負荷は29回×1MiBのローカルdummy GetObject、2CPU/4G、1 mock call、retestなし、正式比較対象外。snapshot1316入力・source26file、新host4f66…、imageb46a…、guest3bc9…に固定した。

native finalized/complete、API29行/incomplete0、captured1991/drop0/read_failedfalse。buffer16384KiB要求/immediate mode/全loopback/payloadを維持し、recorder29接続、各error counter0を確認した。buffer要求値を実割当ての測定とは扱わない。

manifest1580 B、API16492 B、PCAP61014773 B（56〜64MiB範囲）の全実体で長さとSHAがreceiptへ一致し、全verified/collection.complete。保存PCAPの読取り検査もexit0。manifest先行順は固定host sourceの契約へ束縛し、file mtimeは補助証拠として保存した。file IDを含まないauditで実fetch順を直接観測したとは扱わない。

fetch started/completed各1865、delivery read started/observed各2823。timestamp幅331996586683 ns（約332秒）。PCAPの固定file予算495750ms、manifest/API各30250ms、全体600秒の有限予算の下で回収した。同期write/fsync/renameのhard wall capを証明するものではない。

## 制御・回収と範囲

単回exportの同host audit ID回復、native mailbox IDとの区別、forced reader/moved包含、正のfreeze、descendants empty、authorized intent/host startsとtransitionを独立照合。固定observerへ全sampleをreplayし、単一stageとrunのVM binding一致を確認した。

management_stoppedを含むcleanup4flagはtrue、forced_group_stop false/missing_logsなし。これと別にUID999空・cgroup不在・観測port閉を確認した。inventory complete/key不在、control integrity matched/formal_metrics_eligible false。旧証拠/seed-loss全treeとhardlink許可済み物理例外も照合した。

この結果は固定Linux環境・同一負荷の一回のcontrolである。旧large001のdrop155/転送期限超過/management receipt falseという失敗を消さず、任意環境・全証跡量や本番route全般への保証に拡張しない。#64/#65およびPR66/67への受入判断はこの保存証拠のレビューへ委ねる。

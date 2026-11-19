# #65: 大容量 control の capture drop 調査

## 保存証拠から確認できること

[large001結果](LINUX_X86_DELIVERY_RACE_LARGE_001_RESULT.json)では、capture期間は1.102961秒、indexed PCAPは59299901 B、captured1930/drop155、HTTP recorderは29接続・parse/task/connection/admission error各0。PCAP全体は未取得のためパケット単位の欠落位置やburst分布は不明である。PCAPサイズ/記録期間の比は約51.27 MiB/sだが、これは受信時刻分布やディスク速度の実測ではない。

元runの `izanagi.toml` は2 CPU/4G。guest `control.rs::seal` は `tcpdump -n -U --immediate-mode -B 4096`、全loopback、filterなし。stderrはreadiness後も別taskでdrainしている。`finalize` はrecorderを停止・drain後にtcpdumpへSIGINTを送り、drop>0をincompleteにする。保存manifestにshutdown失敗はなく、これだけではCPU競合、ring不足、書込速度のいずれかに原因を断定できない。

## 仮説と有限予算候補

libpcapの[immediate mode説明](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap_set_immediate_mode.3pcap.in)は到着時の即時配送を定義する。[Linux実装](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap-linux.c)ではimmediate要求時にTPACKET_V3を使わずV2を選ぶ。これはupstream sourceであり、元guestの実backend・ring geometryを測定した証拠ではない。

最初の候補はimmediate/filter/snaplen/CPU/負荷を変えず、capture buffer要求だけを4096 KiBから16384 KiBへ増やすこと。4倍・16 MiBの有限要求とし、要求値と実割当ては区別する。51.27 MiB/sでの単純な容量換算は約78 ms対312 msだが、frameの未使用領域・packet overhead・OS制約があるため実際の保持時間や成功を保証しない。これでdropが残る場合、次候補として非immediate/V3と有限flush timeoutを別実験で検討する。複数変数を一度に変更しない。

## 次の検証案（未実行）

新guest/source/binary/imageのprovenanceを分離した新rootでのみ実施する。旧large001を再利用・再実行しない。29回の同一1 MiB dummy GetObject、全loopback・payload付き・drop検査、2 CPU/4Gを維持する。負荷を間引いたり、port filter、snaplen縮小、drop検査無効化で成功扱いにしない。

要求buffer値、tcpdump/libpcap/kernelのversion、loopback MTU、実capture期間、capture/drop/read_failed、recorder counter、API29行と完全性、PCAP実長/SHA/解析結果、freeze、cleanupを保存する。可能ならprivate内容を含まないring設定/CPU・I/O metadataも加え、実割当て未観測を明記する。#64の配送改善と独立にnative capture完全性を判定し、両方を満たして初めて新large trialのcompletedを受け入れる。新VM・guest rebuild・実装変更はまだ開始していない。

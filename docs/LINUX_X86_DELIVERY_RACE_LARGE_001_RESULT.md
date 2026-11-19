# Linux x86 大容量配送 control 001 の失敗証拠

事前の `completed` 期待値は未達。caller 30779 は exit 1、observer 13443 は exit 0 で、同じ Invocation の failed 終端と単一 VM stage を捕捉した。試験の再実行・期待値変更は行っていない。

独立 collector 22930 は exit 0。これは保存証拠の照合成功であり、元試験の成功を意味しない。[結果 JSON](LINUX_X86_DELIVERY_RACE_LARGE_001_RESULT.json) と [collector](evidence/delivery-race-large-001/collect_result.py) に照合範囲を保存した。

- Native recorder: API 29 行、capture 1930 packets、kernel drop 155。buffer 4096 KiB、immediate mode 有効。manifest は finalized だが incomplete。
- 配送: API 16492 B は実ファイルの長さ・SHA と一致。PCAP は index 59299901 B に対し 55607296 B で `transfer_deadline`。manifest ファイルは `upstream_aborted`。PCAP 本体・partial と manifest ファイルは残っておらず、receipt と埋め込み manifest metadata のみ保持する。
- Fetch audit: started 1699、completed 1698、read started 2557、read observed 2556。記録時刻の幅 300313308111 ns。最後の fetch の terminal は欠測として保持する。
- Cleanup receipt: companion/down/up は true、management_stopped は false。UID999・cgroup・観測ポートが実際に回収済みでも、この false を読み替えない。
- Run は aborted、evaluation partial、formal metrics 対象外。runtime の control integrity は unavailable、contaminated と failed_control_operations は null のまま。埋め込み intent の独立照合と正式 runtime 判定を区別する。

固定 snapshot 1311 入力、20 source、既存 smoke/completed 証拠、RAW 削除後に保持した build 証拠を検証した。生成 scenario は 1 MiB のローカル dummy object、agent call 上限 1、retest なし。forced reader 1056、freeze 275538150 ns、descendants empty を確認。秘密鍵の回復・reply の再復号・private stream の再走査は行っていない。

録画 drop、有限配送期限、management stop receipt は別問題として扱う。配送改善は [#64](https://github.com/ieee0824/izanagi-tempest/issues/64) で調整し、この失敗 run は保持する。

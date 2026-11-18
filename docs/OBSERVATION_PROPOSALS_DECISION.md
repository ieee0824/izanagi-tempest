# 追加内部観測と汎用事前 gate の採否

2026-11-18、room #16506/16507 および #16510/#16511の議論と限定棚卸しに基づく技術判断。両追加案は現Phase 1では見送る。検討自体をこの判断で完了し、#7/#36/#41の実装・実受入条件は維持する。

## #16: 固定 release の観測可能性

対象は [追加設計案 #16](https://github.com/ieee0824/izanagi-tempest/issues/16)。固定 LWS `2c0ea463f334f10a562e54f1cdc7ba8a474029e2`、release x86GNU artifact SHA `fca06411b778c978f67222cf878c9053cf37cbd9eefee18b3498122cbe95a46e`。build条件とlockは [artifact manifest](https://github.com/ieee0824/izanagi-tempest/blob/b7df6d7ae26ee416f105ae35529ab0455679938f/docs/LINUX_X86_FULL_ARTIFACTS.json) に固定済みで、artifact未確定は保留理由から外す。

既存 file/readelf/nm だけで調査した。[選別した symbol inventory](LWS_AUTH_SYMBOL_INVENTORY.json) は `.symtab` あり、`.debug_*` sectionなし。`<lws::iam::Iam>::allowed` はaddress `0x349e90` のtext symbolとして残り、principal/Policy::parseにもtext symbolがある。Policy::decisionの独立symbolは今回の名前検索で未検出。未検出をinline確定や観測不能の証明にしない。

固定sourceの [iam.rs](https://github.com/ieee0824/lws/blob/2c0ea463f334f10a562e54f1cdc7ba8a474029e2/src/iam.rs) は allowed(user,action,resource) が各policyを評価し明示Denyでfalse、Allowがなければfalseを返す。これは静的契約であり、実requestの引数・分岐を採取した証拠ではない。HTTP403だけでは明示Denyと暗黙Denyの内部経路を区別できない。一方、固定主体/API/resourceでpolicy条件だけ変える三条件比較は、その観測範囲の応答契約検査として有用であり、既存self-checkを補助する検証方針として維持する。未試行の組合せを実証済みにはしない。

追加debugger観測器は現Phase1では見送る。symbol entryの残存だけでは、PIE relocation・最適化されたRustの&str等の引数ABI・停止やprobeによる影響・policy評価との対応を証明できない。新debugger導入と、その固定binary専用の引数復元・三条件fixtureが追加費用になる。今回はdebugger install/実行、disassemblyによる引数復元、runtime観測をしておらず、実測コストや観測可能性の最終判定は未取得。

既存HTTP/静的sourceで不足する具体例は「そのrequestのどのstatementが実際にmatchしたか」等である。ただし現時点で、それがないため既存条件が具体的に誤受理した例はこの検討に提示されていない。Phase1必須条件の拡張費用を正当化する実例が出た時に再検討する。将来PoCを行うなら、同一binary・非root同一主体/API/resource・Allow/Allow+明示Deny/Allowなしの3条件、1判定entry、1回の観測方法に限定し、作業枠上限1時間を提案する（未実施の上限案であり所要時間実測ではない）。引数復元不能/fixture帰属不明/影響過大なら不成立と記録し、HTTP推定で埋めない。本体改修・新IAM評価器・全APIへの一般化は含めない。

## #17: 追加の汎用事前 gate

[追加設計案 #17](https://github.com/ieee0824/izanagi-tempest/issues/17) の「全操作の内部観測を必須にする新しい汎用事前gate」は現Phase1では見送る。検証runと正式比較の区別自体は維持する。

[IMPLEMENTATION](IMPLEMENTATION.md) の metric_assessment と [report.rs](../crates/tempest/src/report.rs) は観測結果/正式採用/route coverage/実行完了を分ける。未解決の逸脱候補や不完全な経路証拠はunknown、formal_metrics_eligibleを別に扱い、formal_comparison_performedはfalse。schema1の文字列claimだけではroute coverageをverifiedへ昇格しない。[aggregate.rs](../crates/tempest/src/aggregate.rs) はunknownを分母に保持しnot_configuredを分ける。

これらを置換する新しい汎用gateは、証拠収集run自体を止める循環と二重の通過条件を増やす。既存schema/個別profile条件では表せない具体的な誤受理例が提示された時に限って再検討する。#7/#36の既存受入条件、未観測のunknown、正式比較未実施という制限は削らない。見送りは未実装gateを採用済みと扱うことでも、既存正式比較が完成したと主張することでもない。

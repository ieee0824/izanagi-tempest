# B pipe holder scanner source案

room16927/16931へのレビュー用。現行`route_contract::verify_holders`は呼出側の集合を比較するだけで、実走査は未実装である。本案の受入前は`connect_fixture`の拒否を維持する。

## 境界と停止条件

親がpipeを作成する前から、handoff対象全processを専用cgroupへ収容し、fork/FD授受/移動を監督する必要がある。既に第三者へ漏れたpipeを、関連cgroupだけの走査で不存在証明することはできない。親自身をfreezeすることもできないため、親は専用の単一thread supervisorとし、barrier中のfork/dup/close/sendmsgを禁止する実装を先に用意する。B/G内の観測はhost全holder証明の代用にしない。

追加module候補`holder_scan.rs`の入口は、privileged launcherだけが構築できる`StationaryBarrier`、親所有pipe、固定expected集合、絶対期限と上限を受け取る。単なるboolや利用者指定PIDからbarrierを生成しない。barrierが未実装なら入口はUnknownを返す。

1. pidfdと開始tick、cgroupのopen済みFD/dev-inodeを親台帳に固定する。子はhandoff前の専用停止点に留め、不要な親側copyを閉じる。監督process以外の全関連cgroupをfreezeし、`cgroup.events`のfrozen完了を確認する。root cgroupにfreezeファイルがないことから子cgroupも非対応とは推論しない。
2. host PID namespaceのprocfsであること、必要な全PID/threadの可視性と読取権限を確認する。固定上限はPID 4096、thread合計16384、FD合計65536、単一metadata 64KiB、全体2秒を初期案とし、超過はUnknown。上限内のprefixだけで成功しない。
3. 全PIDの全thread FD tableを列挙する。非共有FD tableを持つthreadを見落とさない。現行`Holder`にはTIDがないため、thread tableの共有を証明できないprocessはUnknownとし、初版は単一thread processだけを受け入れる。将来の多thread対応は型変更と別受入が必要。
4. `/proc/PID/stat`の開始tickはcomm内の空白/括弧を考慮してparseし、pidfdの生存と再照合する。cgroup pathは固定root FDから逸脱せず解決し、cgroup dev/inodeも照合する。namespace相対path、削除済みcgroup、曖昧な所属はUnknown。
5. 各FDはproc magic linkの表示文字列だけでpipeと判定しない。追跡先statのFIFO/dev-inodeとfdinfoのoctal flags/access modeを対応させ、親pipeと一致する全dup FDを記録する。O_RDWR、読取失敗、FD消滅/置換はUnknown。対象pipeのendpointをscanner自身へdupするとEOFに影響するため保持しない。
6. PID/thread/FD集合と各identityを二巡で再照合し、全barrier、親FD、pidfd、cgroup所属を最後にも再検証する。差分や欠測はUnknown、固定expectedと異なる確定holderは拒否する。二巡一致だけで静止を証明したことにしない。
7. 成功snapshotはbarrier lifetimeと結び付け、解凍/再handoff/FD変更後に再利用できない。失敗時はrouteを閉じ、管理経路で子を終了・回収してからbarrierを解放する。走査不能を空集合へ変換しない。

全host走査で無関係PIDが消える場合も初版はUnknownとなり得る。成功率を上げるために権限エラーやPID変化を黙殺しない。実用化には生成時からのFD流出防止と、外部holderを排除できるhost観測の範囲をsourceレビューで確定する必要がある。

## 必要な実検査

専用subprocess fixtureで正常handoff、親残copy、同process dup、別process漏出、PID終了/再利用、FD置換、cgroup移動、thread別table、permission不足、走査上限/期限、freeze未完了を検査する。mock procfsのparser検査だけで実holder受入としない。fixture起動・freeze操作はsourceレビュー後で、VMや本番routeの承認を兼ねない。

## child OS backendの読取専用調査

## 実装途中の観測module

room16933を受け、`holder_scan.rs`へ上限付きread/ID列挙、stat開始tick/flags parser、全taskごとの対象pipe FD観測を追加した。`Holder`にTID/task開始tickを追加し、共有tableもtaskごとに区別する。先の単thread限定案は最終方針として採用しない。KCMPによる未観測のtable共有正規化はしない。

これは指定PIDの読取専用観測で、host全PID・cgroup所属・pidfd・実barrier・別FD table負例は未実装。観測結果は`verify_holders`へ未結線で、接続拒否を維持する。自己走査はread_dir自身の一時FDによりUnknownとなるため、実pipe/dup/複数threadのテスト対象は独立subprocessへ置いた。新3testとclippy/fmt/diff確認が成功した。別table負例と全体走査を続ける。

## host metadataの解釈

固定hostの観測値は[metadata](LINUX_DIRECT_B_HOST_METADATA_001.json)に保存した。kernel 6.8.0-147-generic、cgroup2fs、CONFIG_CGROUP_BPF/BPF_SYSCALL/CGROUP_FREEZERはy、BTFあり。unprivileged_bpf_disabledは2。bpftoolは存在し、clang/llcはPATHにない。設定値は実際のconnect4 attach成功を証明しない。`bpftool feature probe`もprogramをloadし得るため実行していない。

固定Izanagi binaryのldd上の依存はloader/libgcc_s/libm/libcで、現capsuleの4 library roleと対応する。ただしlddは動的設定探索やdlopenの完全閉包を証明せず、mount capsule・固定inode/hash・起動時の実検査が残る。Izanagiはhost loopback TCPへ接続するためempty netnsだけでは正対照を満たさない。専用child cgroupで固定sessionportのみ許すBPFと別seccomp/mount/FD制約が候補で、policy load/attach、新VM、auth/APIは未実行。production backend、real catalog/transport、lifecycleと連続run受入は引き続き未達である。

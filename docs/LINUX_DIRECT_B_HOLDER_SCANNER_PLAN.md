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

## 固定dummy試験の凍結と観測結果の寿命

room #17013 の設計。既存のcgroup制御と同様に、親が専用cgroupのディレクトリFDを保持し、そのFDを起点に制御ファイルを開く。親は凍結対象の外に残る。二つのpipeと子を生成する時点から管理側がFDの受け渡しを一手に担い、管理外へのFD授受や子によるcgroup移動を遮断する。親のコピーは期待集合に含めるか、凍結要求前に閉じる。

1. 管理側が移動と引き渡しの受付を閉じ、元のpidfd、PID開始tick、cgroupのdev/inode、期待FD集合を確定する。
2. 専用cgroupの `cgroup.freeze` に1を書き、同じFDから読み取った `cgroup.events` の `frozen 1` を絶対期限まで待つ。欠損、重複、タイムアウトは不確定として終了する。全workerの所属と生存を再確認する。
3. 凍結を保持した管理側だけが観測を実施する。凍結前の台帳と走査後のPID・開始tick・所属・FD集合を照合し、凍結が継続していることを結果消費の直前にも再確認する。同じ管理処理の内部で判定を消費し、解凍後に再利用できる観測証明を外へ返さない。
4. 成功時のみ、結果消費後に解凍して完了を確認する。失敗時は試験経路を閉じ、専用cgroupの停止と回収を行う。監督喪失時も、回収側が元のcgroupと子を特定できるまで接続を開かない。

固定dummyでは、正常な凍結・走査・結果消費・解凍の順序と、凍結確認の期限切れ、対象外cgroupへの配置、追加FD、PID消失を独立ケースで検証する。期限切れは制御読取の模擬だけで実カーネル結果に代えず、模擬試験と固定ホスト試験を別記する。Izanagiの多thread workerを収容する前に、所属とFD流出防止が子の生成時点から成立することを確認する。

進行カウンタは凍結前に増加、凍結確認から走査と判定消費まで不変、解凍確認後に再増加することをそれぞれ観測する。

### 固定ホストの正対照 001

room #17020 の範囲で、ソース `7073986` の `tempest-linux-probe` を `cargo test --offline --locked -p tempest-linux-probe --no-run` でビルドした。実行したテストバイナリのSHA-256は `6b76faf7369f62c93094a5d902bc0e2a8f50506ff014c21492e403128ae68704`。cgroup v2と固定パスの不在を確認し、バイナリを `sudo -n` で起動し、`--ignored --exact cgroup::tests::fixed_dummy_frozen_holder_and_progress --nocapture --test-threads=1` を指定した。単独テスト1件が成功し、終了0。

進行カウンタは凍結前に12から14へ増加し、凍結確認後の走査区間では14のまま、解凍後は14から16へ増加した。凍結中に観測した対象pipeのFDは1件で、内部比較で期待したworkerの書込端と一致した。試験終了時に子を停止しwaitpidを呼び、専用cgroupを回収した。実行後に専用パスが残っていないことを管理処理の外から確認した。結果はroom #17021に報告済み。

この試行は固定workerの正対照を扱う。凍結未完了、所属変化、FD漏出の実機負例と、Izanagiの経路への結線は未検証。

### 固定ホストの拒否試験 001

room #17022 の実機指示に従い、ソース `95a6aaa` をビルドし、`fixed_dummy_rejects_extra_pipe_fd`、`fixed_dummy_rejects_wrong_role`、`fixed_dummy_rejects_exited_worker` をそれぞれ前節と同じ `sudo -n` と `--ignored --exact` の条件で、専用プロセスに分けて一回ずつ直列に実行した。バイナリのSHA-256は `5b761841cabc60d01a4a55a3c828bbc396f3b0618b8fb7f98be2b7f03b7f5cbc`。

- 余剰FDは凍結中のカウンタ10→10、対象pipeのFD 2件を観測し、期待集合との比較で拒否。
- 対象外roleは同じ専用GroupのAに配置したworkerをBとして照合し、走査前に拒否。Group外への移動は未検証。
- 終了済みworkerは元pidfdで終了を観測した後、走査前に拒否。

各テストは終了0。workerの `waitpid` が元PIDを返し、Groupの回収が成功したことを試験内で確認した。外部からも各試行の前後で専用cgroupの不在を確認した。凍結確認の期限切れは今回未試験。

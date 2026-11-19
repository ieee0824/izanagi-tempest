# #65 guest/image 再導出案（未開始）

sourceはdraft PR67の `06563333e895924fb0b3892dfd1213a5285eb33f` を固定する。共有定数でbuffer要求だけ16384 KiBへ変更し、immediate/-U/全loopback/payload/drop判定を維持する。既存fixtureと同じguest source/binaryだったと扱わない。

## Guest binary

新root `/tmp/tempest-capture-guest-build-001` に固定revisionのclean git archive・専用home・空targetを用意する。旧cargo/rustc SHA/versionを確認し、固定Cargo.lockを使ってoffline/locked/release/target x86_64-unknown-linux-gnu/jobs2/-p tempest-guestで構築する。1800秒とTERM10→KILLの有限待機、source全hash/lock前後/実argv-env/ELF-loader-GLIBC/ldd/binary実SHA/容量/実exitを保存する。既存fixtureのbinary metadataを上書きしない。

新sourceでguest tests/fmt/clippyを実施した記録はLinux側の変更branchについて存在し、source commitの正確なbindingを別保存する。新release binary/imageの実測とは区別する。

## Image definition / build

新clean detached worktreeを同revisionで用意し、そのsourceの標準 `image/prepare.py --architecture x86_64 --delivery-race-fixture` を使う。固定ISO、Izanagi/LWS commit、agent/eBPF/HTTP/LWS binaryは旧固定artifactの実SHAを再照合し、新guestだけ新build成果物へ置換する。image.jsonのhelper source commit/tree/dirty=falseは新binaryのsourceへ一致させる。

新definition `/tmp/tempest-capture-definition-001`、実験root `/var/lib/tempest-izanagi-capture-build-001` と専用unitを予定する。実instrumenter/変換後dispatcher/quiesceのhash、親artifact provenance、正確argv/env/許可metadata差分を保存する。定義full validate→新snapshot/UID検査→build-only observer/callerの各監査を経る。完成後は新qcow2の実SHA、installed binary/source metadata/owner-mode/native artifactsをofflineで照合する。旧image/RAW/partition/証拠は不変更。

## 容量 gate

調査時free約9.08 GBで、旧build計画のcopy前20GiB/copy後18GiB条件を満たさない。新imageのinstaller/変換/完成disk各4GiB仮枠、ISO/assets/log/partial/marginを含め、同等の条件を提案する。新guest buildのtargetは別に3GiB仮枠を置く。どちらも実測peak保証ではない。現状ではimage buildを開始しない。追加領域または明示的に範囲を定めた容量対策を別途調整し、旧証拠を自動削除しない。

新runtimeはさらに別root/snapshotでhost PR66 binaryと新guest imageを束縛し、2CPU4G/29回1MiBを維持する。配送と録画完全性は独立gate、元large001失敗は保持する。現時点ではguest release build、prepare、image build、新VMはいずれも未開始。

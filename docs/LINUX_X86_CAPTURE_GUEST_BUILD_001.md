# #65 Linux guest release build 001

room16866指定のPR67 source `06563333e895924fb0b3892dfd1213a5285eb33f` をclean archiveした新root `/tmp/tempest-capture-guest-build-001` で、一度だけoffline/locked/release/jobs2/target x86_64-unknown-linux-gnu/-p tempest-guestを実行した。handle41868は終端exit0。VM/image prepareは未実施。

[provenance結果](LINUX_X86_CAPTURE_GUEST_BUILD_001_RESULT.json)と[実行script](evidence/capture-guest-build-001/build.py)にsource全hash、git tree、lock前後、tools SHA/version、実argv/env、旧host binary・large/completed証拠の前後SHA、容量、binary ELF/lddを保存した。開始前8GiB以上を確認、1800秒/TERM10→KILLを設定した。

binaryは4021520 bytes、SHA256 `3bc9fd0a15aa2f1e0e14f8a33731d0051242ae48ca991e937ad8506ae30d4284`。旧fixtureのguest binaryやmetadataは変更していない。実ring割当て・drop改善・image/VM受入は未確認。

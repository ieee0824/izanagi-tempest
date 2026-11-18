# Linux x86 host CLI build 002

room16859指定のPR66 source `fa3f1d9`をgit archiveしたclean sourceから、既存targetを再利用せずoffline/locked/releaseで単発ビルドした。実handle21188は終端exit0。VMは起動していない。

[実provenance](LINUX_X86_HOST_CLI_002_RESULT.json)にsource全file SHA、git tree、固定cargo/rustc SHA/version、実argv/env、Cargo.lock前後、旧証拠前後SHA、容量、ELF/lddとbinary SHAを保存した。[実行script](evidence/host-cli-build-002/build.py)は1800秒の待機とprocess group TERM10秒→KILLを使う。

binaryは10248336 bytes、SHA256 `4f66f0bd2fca5e98490440c9069da26630c331d9dd56a26dd808c24f1603549d`。source/build rootは `/tmp/tempest-host-cli-build-002-v2`。これは配送予算変更のhost binaryで、guest16MiB変更を含むimageではない。

準備時、初期root002は旧Cargo.lockとの一致を誤って要求してコンパイル前に停止した。旧版との差はprobe workspace crate削除であり、固定revision自身のlockfileを基準とする条件へ修正した。v2も旧private証拠の読取権限でコンパイル前に停止し、既知fileのsudo SHA照合へ修正した。started/targetがないことを確認して準備を再開し、実コンパイルは一度だけ実施した。初期rootと準備途中の証拠を削除していない。

3GiB target予算は事前計画値で、強制quotaではない。build成功は大容量配送・VM受入の証明ではなく、PR66/#64の実VM gateは未実施。

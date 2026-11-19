# B route内部契約 prototype 001

room16913の最初の差分。[設計と未実装OS gate](LINUX_DIRECT_B_VM_ROUTE_PLAN.md)に従い、内部moduleだけを追加した。汎用upstream/新CLI/LaunchPermit生成・変換APIはない。実probeの入口は従来のまま。moduleは未結線であることを明示したdead_code許可を持ち、`connect_fixture`は必ず拒否する。

9新規testは実OwnedFd pipeの向き/別pipe拒否、局所inodeをpeer証明にしないfixture拒否、全holder未知/extra dup/欠測/PID再利用、catalog/schema/digest不一致、foreign run/VM/session/binary/process、management/任意tool/余計なargument、ID対応/再使用/単一inflight/有限予算/絶対期限、oversize/malformed、異常response後の閉鎖を検査する。

```sh
CARGO_HOME=/tmp/tempest-x86-userspace-001/cargo cargo test --offline --locked -p tempest-linux-probe --target-dir /tmp/tempest-b-route-contract-001-target -- --test-threads=1
CARGO_HOME=/tmp/tempest-x86-userspace-001/cargo cargo clippy --offline --locked -p tempest-linux-probe --all-targets --target-dir /tmp/tempest-b-route-contract-001-target -- -D warnings
cargo fmt --all -- --check
```

固定stable toolchain PATHでunit55件とcompile-fail doctest3件が成功し、clippyも成功。途中の並列実行では新test9件は成功したが、既存guard lifetime testがEADDRINUSEで失敗した。並列forkによるFD継承との干渉は仮説で、原因断定や既存guardの修正はしていない。上記serial実行の結果と区別して保持する。

これはunit contract確認で、全holder実走査、OS child egress/config隔離、Izanagi接続、VM、real catalog、CLI/login/secret/live APIの受入ではない。新release binary/VMは作っていない。

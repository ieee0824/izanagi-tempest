# 固定Izanagi最小boot harness

専用host向けの準備中artifactです。上流sourceはgit revで固定し、変更しません。
独立workspaceと独自Cargo.lockを持ち、上流host CLIのlock解決と同一とは主張しません。
通常のTempest workspace buildには含めません。

```sh
cargo build --manifest-path integration/izanagi-bootstrap/Cargo.toml --release --locked
cargo test --manifest-path integration/izanagi-bootstrap/Cargo.toml --locked
cargo clippy --manifest-path integration/izanagi-bootstrap/Cargo.toml --all-targets --locked -- -D warnings
cargo fmt --manifest-path integration/izanagi-bootstrap/Cargo.toml -- --check
```

実行前には[最小boot計画](../../docs/LINUX_IZANAGI_BOOT_PLAN.md)に従い、
binary/image/config/依存のhashと配置、専用systemd unitの回収手順を監査します。
現在は実行しません。host UID999/GID988、guest UID1000、固定pathを前提とし、
任意argumentを受け付けません。guestの`/usr/bin/id` pathもimageで確認する必要があります。

固定imageを認証付きで起動し、`/usr/bin/id -u`のexit0/stdout `1000\n`/stderr空を要求します。
up失敗時もdownを呼びます。`down_returned_ok`は上流APIの結果であり、
QEMU/cgroup/port/auth一時fileの残留なしは外側から独立に確認します。
エラー本文、secret、guest出力はstdoutへ転載せず、結果boolのみ出力します。
実環境は`IZANAGI_SECRET_FILE`を固定dummy secret pathへ設定し、空環境から開始します。
KVM/認証/VM通信の成立はunit testでは検証しません。

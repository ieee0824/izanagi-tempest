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

## bootstrap定義の生成

署名照合済みISO、新規出力directory、同commitのx86_64 musl agentを指定します。
生成器は上流commit/clean状態、template/ISO hash、agent ELF architectureを確認し、
元sourceを変更せずguest user UID1000・qemu_fw_cfg設定を追加します。
完成agentのhashと署名照合の根拠は起動前のmanifest監査で別に照合します。

```sh
python3 integration/izanagi-bootstrap/prepare.py \
  --source /tmp/tempest-izanagi-upstream-review \
  --iso /tmp/tempest-bootstrap-inputs/alpine-virt-3.23.3-x86_64.iso \
  --agent /tmp/tempest-izanagi-bootstrap-agent-target/x86_64-unknown-linux-musl/release/izanagi-agent \
  --output /tmp/tempest-izanagi-bootstrap-definition-001
```

`inputs.json`には元ISO pin/override、source/provision/agent/生成器hashを保存します。
Packer/pluginは1.15.0/1.1.8へ固定し、buildはまだ実行しません。

`bootstrap.service`は監査用の固定property一覧です。常駐serviceとしてinstall/enableしません。
最終起動時に同じpropertyをtransient unitへ渡し、独立したcgroup回収確認を行います。
`/var/lib/tempest-izanagi-bootstrap`配下のprobe/imageはroot所有・専用user非書換えにし、
private run領域と空のread-only share、dummy secretを別に作成してhash/owner/modeを照合します。
これらの配置と起動commandの監査はまだ必要です。

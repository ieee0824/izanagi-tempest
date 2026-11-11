# M0 調査用イメージ

macOS / Apple Silicon の QEMU HVF と Packer 用。Phase 1 の本体イメージではない。
上流の Debian Packer 定義から派生し、起動時の systemd サービス、tcpdump、AWS CLI を調べる。
構築時は Debian パッケージを取得する。実験時には `restrict_network=true` を維持する。

必要なものは Python 3.11+、Git、Rust、cargo-zigbuild、Zig、bpf-linker、LLVM、Packer と QEMU。
上流の [Packer 手順](https://github.com/ieee0824/izanagi/blob/16d0b55947006a166cfa29dcb8bfe71f65f8c36a/packer/README.md)も参照。
この手順は固定コミット `16d0b55947006a166cfa29dcb8bfe71f65f8c36a` を対象とする。

## ビルド入力

以下はリポジトリのルートから実行する。`M0_BUILD` は新規の一時ディレクトリに変更する。
ISO は上流テンプレートの Debian 13.7.0 arm64 netinst と同じ SHA-256 のものを用意する。

```bash
M0_BUILD=/private/tmp/tempest-m0-image-001
mkdir -m 700 "$M0_BUILD"
git clone https://github.com/ieee0824/izanagi.git "$M0_BUILD/source"
git -C "$M0_BUILD/source" checkout 16d0b55947006a166cfa29dcb8bfe71f65f8c36a
rustup target add aarch64-unknown-linux-gnu
rustup toolchain install nightly-2026-02-12 --profile minimal --component rust-src
cargo install cargo-zigbuild --locked
cargo install bpf-linker --locked
cargo build --manifest-path "$M0_BUILD/source/Cargo.toml" --release --locked --target-dir "$M0_BUILD/host"
cargo zigbuild --manifest-path "$M0_BUILD/source/izanagi-agent/Cargo.toml" \
  --release --locked --features ebpf --target aarch64-unknown-linux-gnu --target-dir "$M0_BUILD/agent"
cargo zigbuild --manifest-path "$M0_BUILD/source/izanagi-http-capture/Cargo.toml" \
  --release --locked --target aarch64-unknown-linux-gnu --target-dir "$M0_BUILD/http"
```

eBPF の Cargo.lock は上流で追跡されていない。既存の固定 lock を使う場合は
`source/izanagi-ebpf/Cargo.lock` にコピーする。新規に解決する場合は次で生成し、
生成物を証跡として保存する。後の再現時には同じ lock を使う。

```bash
cargo +nightly-2026-02-12 generate-lockfile --manifest-path "$M0_BUILD/source/izanagi-ebpf/Cargo.toml"
DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/opt/llvm/lib \
  cargo +nightly-2026-02-12 build --manifest-path "$M0_BUILD/source/izanagi-ebpf/Cargo.toml" \
  --release --locked --target bpfel-unknown-none -Z build-std=core --target-dir "$M0_BUILD/ebpf"
```

## 定義生成と Packer

```bash
python3 tools/m0/prepare-image.py \
  --izanagi-source "$M0_BUILD/source" --commit 16d0b55947006a166cfa29dcb8bfe71f65f8c36a \
  --iso /absolute/path/to/debian-13.7.0-arm64-netinst.iso \
  --agent "$M0_BUILD/agent/aarch64-unknown-linux-gnu/release/izanagi-agent" \
  --ebpf "$M0_BUILD/ebpf/bpfel-unknown-none/release/izanagi-ebpf" \
  --http "$M0_BUILD/http/aarch64-unknown-linux-gnu/release/izanagi-http-capture" \
  --lws /absolute/path/to/linux/lws \
  --output "$M0_BUILD/image"
cd "$M0_BUILD/image/packer"
packer init debian.pkr.hcl
packer validate -var-file=m0.pkrvars.json debian.pkr.hcl
packer build -color=false -var-file=m0.pkrvars.json debian.pkr.hcl
```

生成先は `output-debian/debian-aarch64.qcow2`。元のチェックアウトと既存イメージは変更しない。
`inputs.json` のコミット・入力 SHA-256 に加え、完成イメージの SHA-256 とビルドログを保存する。
上流の root パスワードロックと SSH 無効化の最終化を引き継ぐ。
Homebrew / anyenv / Node のセットアップはこの調査用定義では省略する。

`provision.sh` は固定のサービスだけを登録する。起動時に root の uid と epoch を
`/run/tempest-m0/` に書き、loopback PCAP を記録する。M0 のダミー通信を非 root で回収するため、
このディレクトリは0755・PCAPは0644とする。本体ハーネスの保護設計の実装ではない。
任意コマンドを root で実行するヘルパーや sudo 設定は追加しない。

## 実測

設定例の image を完成イメージの絶対パスに変え、認証キーを用意する。
リポジトリのルートから次を実行する。

```bash
python3 tools/m0/collect.py --output /private/tmp/tempest-m0-image-check-001 \
  --izanagi "$M0_BUILD/host/release/izanagi" \
  --config /absolute/path/to/izanagi.toml --boot --guest-capture \
  --guest-file /absolute/path/to/linux/lws --guest-probe tools/m0/guest-lws.sh
```

`summary.json` の起動時 uid/epoch、API 結果、`izanagi-logs/`、制御 `control.pcap` と
ゲスト `loopback.pcap` を比較する。ファイルが存在するだけでは観測成功と判定しない。


`--lws` を指定すると、固定バイナリを root 所有で同梱し、127.0.0.1:4567 に
調査用 strict backend を起動する。起動時の root health 応答を記録し、
OUTPUT の owner ルールで root 以外から同ポートへの接続を REJECT する。
`guest-basics.sh` は LISTEN の存在と接続拒否を突き合わせ、単なる未起動と区別する。
この backend はシナリオ用の seed / recorder を持たず、M2/M3 の実装ではない。

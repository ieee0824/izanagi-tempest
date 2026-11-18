# Linux x86 full guest 準備記録

2026-11-18 UTC、room #16433–16440 の準備段階。追加 install、full image build、VM 起動、livecall は未実施。既存 Alpine boot002 の成功は full Debian の動作・境界の証明には含めない。

## 署名と実 ISO

公式 `https://www.debian.org/CD/verify` と同サイトの公開鍵ファイルを取得し、専用 0700 keyring で primary fingerprint を照合した。

- `10460DAD76165AD81FBC0CE9988021A964E6EA7D`
- `DF9B9C49EAA9298432589D76DA87E80D6294BE9B`

`https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/SHA256SUMS.sign` は後者で GOODSIG/VALIDSIG、exit 0。署名時刻 2026-09-12 16:20:46 UTC、RSA/SHA256。Web-of-trust undefined と、公式 HTTPS 公開 fingerprint との一致を区別する。

| 入力 | SHA-256 |
|---|---|
| SHA256SUMS | de6d320c52b0fa02787e4a6f58115ace89f821865baaeba86115c723f34cbab4 |
| SHA256SUMS.sign | 44e770b3d78c23ae581a9c3153d12b948190c1b9dcfc6d64972a192d2c442ca9 |
| debian-13.7.0-amd64-netinst.iso | a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355 |

ISO download session 83649 は exit 0、実サイズ 792723456 bytes。再読込 SHA も署名済み一覧と一致。入力は `/tmp/tempest-debian-x86-inputs` に保持した。

追加ツール・mount なしに Python 標準ライブラリで ISO9660 directory records と El Torito descriptor を読んだ。BIOS platform 0、validation signature 55aa、default entry bootable 0x88、no-emulation、catalog LBA 1028、boot image LBA 2869。`isolinux/menu.cfg` は BIOS mode と明記し、`txt.cfg` は `/install.amd/vmlinuz` と `/install.amd/initrd.gz` を参照する。ISO9660 の kernel identifier は `VMLINUZ.;1`。

| ISO 内ファイル | bytes | SHA-256 |
|---|---:|---|
| /install.amd/initrd.gz | 24361578 | 8de544ab627ab794504c530c82de621814386b5b67a492f1e3133390c47ea933 |
| /isolinux/boot.cat | 2048 | d0a47b893d7ee0461a9ef0551ed9355c2063f8896eb5947999403a259177d57e |
| /isolinux/isolinux.bin | 38912 | de9e9f48a1132911584675c3dd8a35e5353f4c794d6585b71474d6908735ad5d |
| /isolinux/isolinux.cfg | 157 | 34befdd9cf0c47c265aaa347c2389ec9d99e7304fcabdd1e26b4ecc93e8b9583 |
| /isolinux/menu.cfg | 1189 | 35027599b6399da82871d645a6e0a8034f102defe046766721adf579724e0833 |
| /isolinux/txt.cfg | 121 | 9dad0c526c0221146841abb10ee65da116871e141a06cef41e34041835128c7d |
| /install.amd/vmlinuz | 12142528 | 2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08 |

固定 upstream の実 template bytes を `image/x86_template.py` の production derive に渡し、既存 Packer 1.15.0 の `validate -syntax-only` は exit 0。出力は `/tmp/tempest-debian-x86-syntax/debian.pkr.hcl`。この確認は BIOS のキー入力、実インストール、provision の成功を証明しない。

## source / artifact / tool 棚卸し

Izanagi `16d0b55947006a166cfa29dcb8bfe71f65f8c36a` と LWS `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` は専用 detached checkout、tracked/untracked 差分なし。

| lock | SHA-256 |
|---|---|
| Izanagi agent | 9db17aed3c43477d9bc16dfe65b453b6dc0bb36d4f8e8fc8e7b9814edf200bc6 |
| Izanagi HTTP | c42a9181cf294d7e0ec287029a93027861a45abd485bafd7640a1023a6cd3296 |
| LWS | cf7d8286d8563d5805614ae7992d6ea7fe3d7ec94e4b050240b402e687f9cbae |
| Tempest | ca753c1880e2cc493369ea6143698bcf60c7456ecdc79767c15cc523776cae77 |

既存 bootstrap agent は default features の musl artifact であり、full tracing 用に採用しない。full agent は `--features ebpf` の別 artifact が必要。HTTP/eBPF/LWS の今回採用する x86 artifact は未準備。既存 debug tempest-guest は今回の release provenance と未結合のため棚卸し参考に留める。

host は stable Rust 1.100.0、GNU/musl x86 targets、gcc/cc 13.3、make、perl、pkg-config、zstd、tcpdump、QEMU 8.2.2 を持つ。go/zig/cargo-zigbuild/bpf-linker/clang/llvm-config/aws は PATH にない。nightly は未導入。SQLCipher/OpenSSL は LWS の vendored dependency であるため libssl-dev 等の追加を推測で決めない。Aya についても libelf-dev の必要性は未確定。

固定 upstream release workflow は nightly-2026-02-12 + rust-src と bpf-linker v0.11.1 の x86 musl prebuilt を採用している。archive URL は `https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst`、固定 SHA は `e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8`。次段階では archive 照合と binary の依存検査を先に行い、必要性のない LLVM APT 導入を避ける。まだ取得・導入・実行していない。

host Python cryptography は 41.0.7、image/requirements.txt は 50.0.2 固定。専用 venv で固定 requirements を導入する候補とし、global Python を更新しない。

## 次段階の具体化

次の build は監査対象の候補であり未実行。専用の新 target/output directory と compiler version、features、lock、source commit、成果物 SHA を記録する。

```sh
cargo build --manifest-path "$IZANAGI/izanagi-agent/Cargo.toml" --release --locked --features ebpf --target x86_64-unknown-linux-gnu --target-dir "$ARTIFACTS/agent"
cargo build --manifest-path "$IZANAGI/izanagi-http-capture/Cargo.toml" --release --locked --target x86_64-unknown-linux-gnu --target-dir "$ARTIFACTS/http"
cargo build --manifest-path "$LWS/Cargo.toml" --release --locked --target x86_64-unknown-linux-gnu --target-dir "$ARTIFACTS/lws"
cargo build --release --locked -p tempest-guest --target x86_64-unknown-linux-gnu --target-dir "$ARTIFACTS/guest"
```

変数の絶対パスと権限・容量は実行前の具体 snapshot で確定する。eBPF は upstream が Cargo.lock を追跡していないため、初回解決内容と hash を明示して固定した後、nightly + rust-src、bpfel-unknown-none、`-Z build-std=core`、`--locked` で独立生成する。ELF machine 247 だけでは x86 probe 引数 ABI や実 kernel load の妥当性を証明しない。

userspace は ELF machine 62、interpreter、NEEDED、GLIBC symbol requirements を記録して guest ABI と照合する。既存 Makefile の既定 arm64/zig target をそのまま実行しない。Debian template の agent service は `IZANAGI_ALLOW_ALL_COMMANDS=1` を設定しており、minimal Alpine の id allowlist とは異なる契約である。

## full VM 再検証計画

- M3 mailbox の host 0700/0600、guest root owner、mapped-xattr、actor uid 1000 と host uid 1000 の衝突を実 VM で検査する。固定 doas dispatcher 以外・native helper 直接実行・tokenless・別 command を拒否する。
- AES-GCM mailbox の request/reply、固定 padding、nonce、replay、応答喪失時の同一 ID 回復、異常・timeout lease と cross-run reset を実 fixture で検査する。secret は argv/env/log に出さない。
- backend 4567 と RPC 9001 の IPv4/IPv6、guest gateway 経由 host forward、proc environ/FD、fw_cfg、cgroup 書込を実通信/実 open で検査する。外部通信拒否は dummy canary の正常な positive control と組にし、到達不能を拒否と誤認しない。実 AWS は利用しない。
- `--features ebpf` agent の TraceStarted、関連 PID/path event と HTTP sidecar の dummy HTTP capture を検査し、Ready のみで tracing 成功としない。guest/host clock と timeout/kill/reap の証拠を別に記録する。
- CLI の session 保存先には専用の writable private HOME が必要。bootstrap library の `/nonexistent` HOME を流用しない。KVM は専用 uid 999 のままとし、ubuntu に KVM membership を追加しない。
- Packer の HTTP/SSH/VNC は loopback 固定、build 時の package fetch と実験時 restrict=on を区別する。固定 immutable 入力、Invocation、listener、終了状態、cgroup/子 process 回収を採取し、旧 artifacts/evidence を保持する。

追加 install/full build/VM の具体 command と snapshot は、この準備・依存閉包・成果物のレビュー後に確定する。

## bpf-linker の非実行検査結果

room #16446 の監査後、download session 97993 は exit 0。専用 0700 `/tmp/tempest-x86-full-tool-inputs` へ取得した archive は 27975135 bytes、前記固定 SHA に一致した。member は `bpf-linker` の通常 file 1 件（103959440 bytes）のみ。link/special entry はなく、全展開せず選択 bytes を O_EXCL|O_NOFOLLOW、0600 の `bpf-linker.inspected` へ読み出した。

binary SHA-256 は `c974140662f783c37bf0267436409caa8f4708ec10b558d9d1c594385489fe2f`。file/readelf は ELF64 little-endian x86-64 EXEC、静的リンク、PT_INTERP なし、dynamic section なし。PATH 配置・実行は未実施。この検査から追加 host LLVM APT を必要とする動的依存は見つからなかった。

nightly の公式 manifest と sidecar も独立照合し、SHA-256 `3addb500ea35b558cb820e44c98217aa931a0eab0066233b3e8254d91ad6566e` に一致した。これは HTTPS/sidecar の照合であり署名検証ではない。

| nightly-2026-02-12 archive | manifest xz SHA-256 |
|---|---|
| rustc x86_64-unknown-linux-gnu | ecff4a1dd40734c2614c56b28f265eb8d771d7dd1a3c3cb4ed0740d95deec8a7 |
| cargo x86_64-unknown-linux-gnu | c8ec4b723d4d1085f3f5dbad8ef0f4ec5337098db13e68c85ef2c3d149ac168b |
| rust-std x86_64-unknown-linux-gnu | 6cbe23fabbcd1b519b8310b72722c6d2ed5107fb172633d54141f74cf70cc51b |
| rust-src | a806f00ff962f3460447aee4699a17b74a81e02679381287eccada79a241e643 |

nightly の導入は未実施。既存領域とは独立した `/tmp/tempest-x86-full-rust/{rustup,cargo}` を候補とし、具体 command を room へ提示した。

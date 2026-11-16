# KVM固定検証器 artifact監査（build-only）

対象実装commitは`86f4624`、native Linux/x86_64 debug ELFです。
`target/debug/tempest-kvm-probe` SHA256:
`02c497a648dfff4bb6622f1f5db4edac7c781150bbd355428d060d2d629ae0bf`。
device実行・専用user作成・installは未実施です。

## 検証

`cargo fmt --all -- --check`、`cargo build --workspace --locked`、
`cargo clippy --workspace --all-targets --locked -- -D warnings`は成功しました。
`cargo test --locked -p tempest-kvm-probe`は11 tests成功、workspace全testは実行中です。

| 根拠 | 確認範囲 |
| --- | --- |
| C/Rust compile-time照合 | 実使用layout/offset/ioctl値、native target制約 |
| 固定guest/exit parser | IO→HLT、余分exit、不正方向/port/count/data、offset境界の拒否 |
| 純粋identity負例 | root/一般UID/余分group/saved UID/shell不一致の拒否 |
| 実dummy child | 正常・失敗・期限kill/reap・gate EPIPE、primary/cleanup独立判定とCLI exit |
| 固定record負例 | 長さ/magic/errno/terminal不整合の拒否 |
| 実FD/map負例 | 早期失敗のFD閉鎖、mincoreによる解放観測、munmap EINVALと残留の検出 |
| slot guard代替FD負例 | primary EPERMと削除ENOTTYを別保存。実KVM slot削除の証明ではない |

実VM作成/TSS/RAM登録/vCPU作成/run mmapの各stageで、実行本体へ注入して
同じ回収経路を検証する網羅的failure injectionは未完です。11 testsをその代替とは扱いません。

## 配置案（未実行）

管理者は専用user作成checkpoint後、`/var/lib/tempest-kvm-probe`を
root:tempest-kvm 0750、配下`probe`をroot:tempest-kvm 0550に固定します。
全ancestorのowner/modeと専用userの通過可能性、source/installed SHA256一致を検査します。
共有workspaceのbinaryを専用userへ直接実行させず、環境は空、引数なしで扱います。
dynamic loader/library closureとinstall時再検証もartifact監査の対象です。
実行commandは残る監査後に確定し、現段階ではinstall/device実行を行いません。

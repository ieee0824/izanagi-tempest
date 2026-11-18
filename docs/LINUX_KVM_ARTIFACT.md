# KVM固定検証器 artifact監査・最小VM実測

対象実装commitは`623b34b`、native Linux/x86_64 debug ELFです。
`target/debug/tempest-kvm-probe` SHA256:
`d6c746bd13d8b219eb11086d83d50ee03b38a90989179cd6c5563f69ef6089e3`。
2026-11-18に専用user作成、固定配置、実deviceでの最小VM実行まで確認しました。

## 専用hostでの実device実測（2026-11-18）

[専用userとAPI12](LINUX_KVM_ADMIN_GATE.md)、[固定配置](LINUX_KVM_DEPENDENCIES.md)の
監査後、room #16328の指示で次を1回実行しました。直前にinstalled SHA256を上記固定値へ再照合しています。

```sh
/usr/bin/sudo -n -u tempest-kvm /usr/bin/env -i /usr/bin/timeout --signal=TERM --kill-after=2s 15s /var/lib/tempest-kvm-probe/probe
```

exit 0、elapsed 0.027019秒、stderr空。固定stdoutは次のとおりです。

```json
{"deadline_exceeded":false,"child_terminal_reaped":true,"explicit_cleanup_complete":true,"primary_errno":null,"cleanup_errno":null}
```

実行前後の`ps -eo pid,ppid,uid,comm,args`でUID999のprocessは双方なしでした。
固定実装によるVM/vCPU/RAM、IO→HLT、最終register照合と明示回収の正常経路を実deviceで通過しました。
実deviceでのstage別異常注入は行っていません。Izanagi起動、image再構築、credential/live-callの証明にはしません。

## 検証

`cargo fmt --all -- --check`、`cargo build --workspace --locked`、
`cargo clippy --workspace --all-targets --locked -- -D warnings`は成功しました。
`cargo test --locked -p tempest-kvm-probe`は12 tests成功。
`86f4624`時点の`cargo test --workspace --locked`も全体exit0で完了し、
最新版でもworkspace全target clippyとformatを再確認しています。

| 根拠 | 確認範囲 |
| --- | --- |
| C/Rust compile-time照合 | 実使用layout/offset/ioctl値、native target制約 |
| 固定guest/exit parser | IO→HLT、余分exit、不正方向/port/count/data、offset境界の拒否 |
| 純粋identity負例 | root/一般UID/余分group/saved UID/shell不一致の拒否 |
| 実dummy child | 正常・失敗・期限kill/reap・gate EPIPE、primary/cleanup独立判定とCLI exit |
| 固定record負例 | 長さ/magic/errno/terminal不整合の拒否 |
| 実FD/map負例 | 早期失敗のFD閉鎖、mincoreによる解放観測、munmap EINVALと残留の検出 |
| slot guard代替FD負例 | primary EPERMと削除ENOTTYを別保存。実KVM slot削除の証明ではない |
| 同じ本体へのstage別注入 | 正常+16失敗経路。実memfd/匿名mapの回収をfstat inode/mincoreで独立確認 |

stage backendはAPI/extension/map size、VM/TSS/RAM/slot/vCPU/run map、sregs/regs、
IO/HLT/最終regs、slot除去へ失敗を注入し、同じ実行本体からの回収を確認しています。
各試験では指定stageへの到達を必須にします。ioctlはmockなので、実hardwareの
VM作成・登録・実行・slot削除成立の証明とは扱いません。
stage別異常系はこのunit試験の範囲であり、実device正常経路とは区別します。

## 独立Linux CI

`dfe9573`でstage別primary/cleanup期待値と初期device代替FDの回収観測を強化しました。
これを含む`3161333`の[GitHub Actions実行](https://github.com/ieee0824/izanagi-tempest/actions/runs/43786676394)で、
Ubuntu 24.04/x86_64、Rust 1.100.0の12 tests、当該crateのall-target clippy、workspace fmtが成功しました。
共有実行本体へのstage注入とprimary/cleanup独立判定のテスト実行をログで確認済みです。
KVM deviceは開かず、実hardware gateや専用hostのbinary hash・loader/library監査の代替にはしません。

## 固定配置（実施済み）

管理者は専用user作成checkpoint後、`/var/lib/tempest-kvm-probe`を
root:tempest-kvm 0750、配下`probe`をroot:tempest-kvm 0550に固定します。
全ancestorのowner/modeと専用userの通過可能性、source/installed SHA256一致を検査します。
共有workspaceのbinaryを専用userへ直接実行させず、環境は空、引数なしで扱います。
dynamic loader/library closureとinstall時再検証もartifact監査の対象です。
実施結果と再照合は[依存・配置監査](LINUX_KVM_DEPENDENCIES.md)、実行結果は上記に記録します。

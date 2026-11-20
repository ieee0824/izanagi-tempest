# Issue #36 gate台帳

最終更新: 2026-11-19、branch `pronnia/linux-direct-stage`。
dummy HOME最終独立実測は`d598243`、KVM build-only実装は`623b34b`、
失敗時assert強化は`dfe9573`、これを含む`3161333`の
[Linux CI](https://github.com/ieee0824/izanagi-tempest/actions/runs/43786676394)で12test・clippy・fmt成功を確認しました。

本書は[Issue #36](https://github.com/ieee0824/izanagi-tempest/issues/36)の旧完了条件と、
subscription OAuthをTempestが読取・copy・parse・relayしないLinux direct方針への変更後のgateを対応付けます。
Linux dummy probeの成功をClaude、credential、VM、外部通信を含む本番隔離の証明へ拡張しません。

## 状態

| Gate | 状態 | 根拠と残り |
|---|---|---|
| Linux固定A/B/Gの基本隔離 | 実装・実測済（dummy限定） | UID、mount/PID/net namespace、cgroup、seccomp、権限drop、親proc/fd/env、ptrace/signal、外部network/KVM等の負例を専用Linuxで実測。READMEのWIP範囲に限定する |
| 異常時回収と再加入 | 実装・実測済（dummy限定） | `651fd36`のprimary faultと`37b1075`のsnapshot race。後者はルーム#16180、Issue comment 6903490736。probeの保守的残留後にfixture限定回収した結果であり、自動回復ではない |
| 固定CLIのcredential保存先・必要access | 部分実測 | Claude Code 2.1.325の既存loginで非秘密auth statusとmetadata不変を確認（Issue comment 6877497099）。fresh専用configの保存挙動は未測定 |
| 通常HOME・既存設定・既存MCPの非到達 | dummy checkpoint実測済・本番未達 | `71ab7a4`でsynthetic HOME 9分類の各run前後正読取、A/B/G負例とprivate HOME正例を実測。実HOME/Claude探索は未検証。[範囲とhash](LINUX_STATE_ISOLATION.md) |
| owner-private configの生成、login、検査、run、cleanup | ログイン前の生成・検査済 | PR #81（`102a81c`）で所有者、ディレクトリ0700、ファイル0600、空の設定と負例を Linux で確認。PR #83（`17f0655`）で空設定の生成と監査を追加し、独立 Linux worktree で回帰テスト2件に成功（cc-sakura 投稿 17347）。ログイン後の設定・保存・回収は未検証。fresh loginと本番callは段階承認#15836/#15839の範囲外 |
| 専用 UID での固定 CLI の起動 | オフラインの版確認済 | 専用 Linux x86_64 で実効 UID/GID 999:988、バイナリ所有 root:988・0750、`--version` は `2.1.325 (Claude Code)`、終了コード0。SHA-256 は元実体と一致し実行前後で不変。空の設定の監査は前後で一致し、IPv4/IPv6 のソケット作成を拒否した。[Issue #36 の実測記録](https://github.com/ieee0824/izanagi-tempest/issues/36#issuecomment-7009980793) |
| run間のstate独立性 | dummy checkpoint実測済・本番未達 | `c5e26e0`でdigest/mount再照合込み両run各21check true。最終独立driver `d598243`もcapture2/read18/各21check・guardian回収・ROOT/RUN不在を実測しルーム#16256へ報告。合成ファイル境界の拡張後は各 run 30 項目。[検証範囲と実行条件](LINUX_STATE_ISOLATION.md#合成ファイル境界の監査)。Claude session保存停止は未検証 |
| subscription通信境界 | 合成試験済・Tempest 未結線 | 専用 Linux の一時ネットワーク名前空間で、親から許可先への受理1件、親から未許可先と子から両宛先への受理0件を確認。拒否カウンタは親1・子2で、子の stdio 応答と試験資源の回収も確認した。[固定合成試験の記録](https://github.com/ieee0824/izanagi-tempest/issues/36#issuecomment-7031607288)。PR #98 では合成試験の起動前検査、PR #99 では固定オフライン診断の独立した名前空間検査と拒否時の回収を確認した。本番の Claude 親の宛先制限と MCP 子の外部通信拒否は未検証。OAuth token を Tempest に通さない |
| direct profile・report schema | 純粋型・負例実装/レビュー済 | `b27e88d`で独立profile/report型・semantic validator・7test。request catalog/schema/header/count/retry/budget強制はUnobserved必須、既存relay契約へ変換不可。実artifact生成・正式比較受入は未完。[schema](DIRECT_PROFILE_SCHEMA.md) |
| 秘密の成果物・log・process metadata非露出 | 固定ダミーの公開出力を実測 | PR #90（`c1c2f29`）で通常出力、内部報告の途中 EOF、容量超過4ケースを含む198項目を専用 Linux で確認。公開出力に合成マーカーや許可外のトップレベル項目は出ず、回収も確認した。[実測記録](https://github.com/ieee0824/izanagi-tempest/issues/36#issuecomment-7031246241)。実 credential を使う試験は未実施 |
| 固定オフライン診断の配置失敗時の回収 | エラー復帰時を実測 | PR #92（`b3b98c4`）で1件目の bind 後に2件目の SHA-256 不一致を検出し、一時マウントと作業領域を回収。直後の正常試験と固定 CLI のオフライン起動も成功。[監督の強制終了時の独立回収](https://github.com/ieee0824/izanagi-tempest/issues/93)は PR #95（`28c0ed7`）で、起動許可前の世代限定回収、終了確認済みの診断失敗後の回収、終了未確認時の領域保持を専用 Linux で確認した |
| 固定 Izanagi MCP のローカル stdio | 固定ホストで正例・遮断・回収を実測 | `1c05b83` で `initialize`・`tools/list`・stdout EOF を確認。`73a440c` で余分な要求パイプ FD を観測して送信を許可せず、`059fa0f` で照合失敗から cgroup を停止し、元の両子と試験用パスを回収。[試験記録](LINUX_DIRECT_B_VM_ROUTE_PLAN.md) |
| 固定 VM 受信試験の起動前確認 | 専用イメージで実測済 | `b6af0be` で同じ実セッションから専用フラグ、ゲスト ELF、空の記録ディレクトリ、boot ID を照合。独立 observer は終了状態を取得できず、同じ Invocation の正常停止は PID 1 の journal で確認した。[起動確認001](LINUX_DIRECT_B_VM_ROUTE_PLAN.md#専用-vm-の起動確認001) |
| 固定 VM 受信試験の4区間照合 | 専用 VM で実測済（固定ダミー） | PR #38（`279168b`）で同一 VM の4区間を完走。ゲスト要求 [1,1,0,1]、別 listener の受理 [1,0,0,1]、拒否は TCP `EPERM`。PR #80（`fea4a51`）で監督強制終了後の中継子・pin・cgroup の回収、独立管理経路、正常停止を追加実測。[試験記録](LINUX_DIRECT_B_VM_ROUTE_PLAN.md) |
| 別 VM への固定管理接続の拒否 | 専用 Linux で2台実測済 | PR #108（`0c990f5`）。A への認証済み接続を維持し、B への接続だけを拒否。制限の前後で B の認証済み応答を確認し、両台の停止後に資源を回収した。対象はローカルの固定管理経路。[試験記録](LINUX_DIRECT_B_VM_ROUTE_PLAN.md#2台の実-vm-での管理接続の許可と拒否36) |
| 本番B固定VM経路 | 結線・実測未達 | Linux direct probe から同じ run の Izanagi/guest/HTTP MCP へ到達する経路と、他の宛先への非到達を検証する |
| KVM段階gate | 固定最小VM・Izanagi dummy最小経路実測済 | #15865/#15872承認に従い専用user/API12/固定最小VMを確認。[KVM実測](LINUX_KVM_ARTIFACT.md)と[boot002](LINUX_IZANAGI_BOOT_002.md)の認証Ready・固定guest UID1000・down・独立回収を別証拠で記録。full guestとVM外host endpointの選別dummy検査は後述。本番B/VM結線は未達 |
| x86_64 guest/image再構築 | 固定build・選別dummy VM検査済、全受入は未達 | [full build003](LINUX_X86_FULL_BUILD_003.md)と[smoke002](LINUX_X86_IMAGE_SMOKE_002.md)で固定artifact/読取境界、実agent hash、owner/firewall/doas/mailbox、200/403/501、quiesce/export/API/PCAP、nonce/PID/path付きeBPFを確認。observer GC unknown等は別終了証拠と区別。全route/全期間・sidecar・外部対照・clock一般保証には拡張しない |
| runtime reset/主体/presence | 固定mock検査済、正式model未達 | [正常2run/reset](LINUX_X86_RUNTIME_NORMAL_001.md)、[seed返信喪失](LINUX_X86_RUNTIME_SEED_LOSS_001.md)と[独立予約拒否](LINUX_X86_RUNTIME_RESERVATION_001.md)、[4presence](LINUX_X86_RUNTIME_PRESENCE_001.md)を監査。#14/#15は完了。seed-loss旧trialの失敗/旧retry欠測は保持 |
| 配送方式・露出調査 | #13調査完了、未確認範囲あり | [配送証拠表](ISSUE-13-DELIVERY-EVIDENCE.md)とPR #59で方式/上限/障害処理を設計へ反映。exec保存scanと[proc003](LINUX_X86_PROC_EXPOSURE_003.md)の3時点限定観測を確認。PIPE/FD内容/短命native/全期間等は未測定のまま。強制競合の限定fixture結果は次行へ分離 |
| 強制配送競合と大容量回収 | 固定fixtureの小容量・大容量control実測済 | [専用smoke](LINUX_X86_DELIVERY_RACE_SMOKE_001.md)と[completed試験](LINUX_X86_DELIVERY_RACE_COMPLETED_001.md)で単回export・forced reader回収・同ID認証済み再読取・3file receipt・fresh retestを監査。[large001](LINUX_X86_DELIVERY_RACE_LARGE_001_RESULT.md)は300秒転送期限とkernel drop155で事前completed期待に失敗。[新large control](LINUX_X86_CAPTURE_LARGE_001.md)では同一29×1MiB負荷・2CPU/4GiBでdrop0、PCAP61,014,773Bを含む3file実長/SHA・全receipt一致、約332秒で回収。management正常停止と独立回収も照合。PR #66（07e03c2）/#67（c0118dc）をmainへmergeし、#64/#65はclose。observer GC終端unknownは別trusted終了と区別。旧失敗/partial/unknownを保持し、全負荷・全期間の保証へ拡張しない |
| HTTP sidecar実起動 | 固定loopback限定で実測・監査済 | [sidecar001](LINUX_X86_SIDECAR_001.md)の1VMで正常転送1/別port failed1/非許可Host rejected1、receiver対照[1,1]とfresh telemetry bindingを確認。保存fixture/audit再計算・13exec/26stream scan・1311入力不変と別終了回収を監査。PR #61で範囲をmainへ反映。observer終端unknown/全argv・親実体・exe直接hash未測定は保持。外部egress/分類精度/全writerは未完 |
| VM外host endpointの拒否対照 | 当該endpoint限定で実測・監査済 | [host-endpoint001](LINUX_X86_HOST_ENDPOINT_001.md)の1VMでhost前後対照2/guest loopback成功、10.0.2.2対象portへのerrno111拒否・追加accept0を確認。独立root ack/PID/cgroup/全owner/inodeとready-live-closed、停止後counterを保存再計算。PR #63で範囲をmain記録。Internet全般/本番MCP/B通信へ一般化しない |
| owner手動login後の初回1 run | 未承認・未実施 | usage credits無効のowner確認を外部前提とし、fresh loginと1 runは別承認が必要。反復・複数modelも別承認 |
| Issue #7での最終受入 | 未完 | direct接続で失うrequest単位監査と正式比較条件を再合意する必要がある |

## 次の段階実装gate

### 固定 CLI のオフライン起動に使ったファイル

固定 Linux x86_64 版 2.1.325 は、経路のないネットワーク名前空間、
空の環境、新規 HOME、空の専用設定で版確認とヘルプ表示に成功した。
ヘルプは `--strict-mcp-config` が明示した MCP 設定だけを使用することと、
`--setting-sources` が設定の読み込み元を指定することを説明する。
[固定版の測定記録](https://github.com/ieee0824/izanagi-tempest/issues/36#issuecomment-7034854488)

同じ固定版を通信遮断・資格情報なしで起動した試験（cc-sakura 17512）では、
制限なしの対照で user/project/local の設定とプロジェクトの `.mcp.json` を
読み取り用に開き、固定 stdio MCP を起動した。空の `--setting-sources` と
厳格な MCP 指定で空の MCP 定義を渡すと、`.mcp.json` の open と MCP 起動は
観測されなかったが、user/project/local の設定の open は観測された。
同じ制限下で固定 MCP を明示すると起動と `initialize` を観測した。
全ケースが未認証で終了し、設定値の適用と認証後の挙動は未確認。
通常設定への非到達は OS 側の隔離で検証する。
[Issue #120](https://github.com/ieee0824/izanagi-tempest/issues/120)

既存 relay の起動引数には `--bare` がある。Anthropic の公式文書では
このモードはサブスクリプションのログイン状態を使用しないため、
直結の起動引数は別に検証する。
[Claude Code の bare モード](https://code.claude.com/docs/en/headless#start-faster-with-bare-mode)

[Issue #36 の測定記録](https://github.com/ieee0824/izanagi-tempest/issues/36#issuecomment-7010159462)と
cc-sakura 投稿 17357 に基づく Linux x86_64 の `--version` 用の一覧です。
固定 CLI を専用設定とともに新規 root に配置し、下記の読み取り専用入力で起動できました。
ホストでの共有ライブラリの解決先は `/usr/lib/x86_64-linux-gnu/` 配下です。
試験 root 内の配置先は `/lib/x86_64-linux-gnu/` 配下で、CLI は `/bin/claude` です。

| 入力 | SHA-256 |
|---|---|
| Claude Code 2.1.325 | `0dc4f4a9a165fc60746d7ae8489712e5fc352f1e7ad4eb22e7141bd0812eb0cf` |
| `librt.so.1` | `5a00236da5864e8d1123d74e616713110708d6e3e604188f4f256dab4c6941d4` |
| `libc.so.6` | `755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a` |
| `ld-linux-x86-64.so.2` | `5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f` |
| `libpthread.so.0` | `cd34f895c9d2aa669d5d2654bed6b71210fc9003c3a1e96bb5311a40feb86039` |
| `libdl.so.2` | `4dbcca3c01ca84d092b5b7b2610f5835b55fc70a0288dd9d766b40ac9386e2d9` |
| `libm.so.6` | `5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a` |

ELF の `PT_INTERP` が指定する `/lib64/ld-linux-x86-64.so.2` にも上表と同じローダーを配置しました。
試験では `ld.so.cache`、`/etc`、`/proc`、`/dev`、通常 HOME を配置せず、起動後に一時 root を回収しました。
個々のファイルの必要性、動的ロード、ログインやモデル実行時の依存は未確認です。

cc-sakura 投稿 17359 のディスク上の再現では、CLI 単体が 365,842,960 B、全ファイルの合計が
369,441,675 B、実割当が 369,491,968 B でした。既存 capsule の 16 MiB tmpfs には全ファイルを
コピーできません。親が照合した読み取り専用のスナップショットから個別ファイルを bind mount する案を
検討します。この方式での起動とマウント属性の照合は未実施です。

### 残りの受入

synthetic HOME非到達と連続2 runのstate独立性は`d598243`までのdummy実測で確認済みです。
実Claude設定・credential・sessionへの成立は未検証のままです。

KVM固定プローブの専用user・配置監査・実device正常経路は確認済みです。
最小bootstrap image生成・最終化と回収は[build003](LINUX_BOOTSTRAP_BUILD_003.md)で確認済みです。
systemctl終了属性の取り逃しと、trusted journal/clientによる別証拠の関連付けは区別しています。
固定Izanagiの[boot002](LINUX_IZANAGI_BOOT_002.md)で認証Ready・固定guest UID・downが成功しました。
続いて固定full artifactsと派生Debianのimage生成まで完了しました。
[build003結果](LINUX_X86_FULL_BUILD_003_RESULT.json)のservice成功・exit0はtrusted journalと
同InvocationIDへ束縛し、caller exit143およびobserverの最終属性unknownとは区別します。
image生成の成功を、そのimageの実VM隔離・実トレース採取成功へ拡張しません。

1. full image smoke002と正常runtime/reset・seed返信喪失/独立予約拒否・4presence・proc003の限定dummy結果を保存し監査した。
   単一QEMU lifetimeはPID/starttime/cwdで拘束し、observer GC終端unknownとtrusted終了/独立回収を区別する。
2. HTTP sidecarとVM外host endpointは専用modeの単発結果を取得・監査済み。強制配送競合は専用smoke/completedの限定fixtureで確認したが、旧大容量controlの失敗を保持し、修正後の新controlで同一負荷のdrop0・全証跡回収とcleanupを確認した。Internet全般/本番Bへの一般化、clock一般性、全route等は未確認のまま残る。
   通常smokeのHTTP/PCAPやTraceStartedだけで代替しない。制限解除・書込共有・実modelへfallbackしない。
3. 本番B固定VM経路、direct egress、owner-private config/login/session/cleanupの本番受入を実装・レビューする。
   fresh login/live-call/反復比較は既存の段階承認の範囲外であり、dummy結果から認証や正式比較成功を推定しない。

dummy HOMEの受入範囲は[Linux HOME・run state隔離gate](LINUX_STATE_ISOLATION.md)に固定します。
本番B/VMへの結線、fresh login、subscription live-call、正式比較は未達です。
KVMの永続host変更は承認済み設計に従う管理者checkpointとして分離し、
失敗時にroot QEMU、TCG、既存macOS/aarch64実測へfallbackしません。

### 固定 Claude バイナリのオフライン再現

専用 Linux x86_64 で、事前に照合した Claude Code 2.1.325 の実体を
root 所有・0555 の `/var/lib/tempest-claude-offline/claude` に置く。
ファイルをネットワークから取得する処理は含まない。固定 CLI と共有ライブラリ
6点のパス・容量・SHA-256 は、以下のビルド対象の固定表にある。

```sh
cargo build -p tempest-linux-probe --bin tempest-claude-offline-version --locked
sudo -n target/debug/tempest-claude-offline-version
cargo test -p tempest-linux-probe --locked
cargo clippy -p tempest-linux-probe --all-targets --locked -- -D warnings
```

専用ホストで再現した結果は `2.1.325`、UID/GID `999:988`、
tmpfs 使用量 4096 B・17 inode、exit 0。16 MiB／128 inode の tmpfs に
8ファイルを個別に bind し、ローダーの2パスは同じ検査済み inode を参照した。
実マウント表は root と8配置に一致し、全マウントで ro/nosuid/nodev を
確認した。空設定の検査は実行前後で一致し、試験用マウントと領域を回収した。
ソース一式と staging は root 管理で、試験を開始するたびに digest を照合する。
ホストの通常 HOME と既存設定を持ち込まず、新しいネットワーク namespace
で固定の `--version` のみを起動する。実ログイン、モデル呼び出し、
`--version` 以外の実行に必要な動的依存は未検証。

合成データによる bind の回帰も専用 Linux で実測した。同じファイルを
2箇所に bind し、dev/inode 一致と書込 open の `EROFS` を確認した。
この特権テストは通常の `cargo test` ではスキップする。
再実行には `cargo test -p tempest-linux-probe --lib --locked --no-run` が
表示するテスト実行ファイルを root で起動し、
`--ignored --exact claude_offline::tests::synthetic_loader_aliases_are_read_only_binds_of_the_same_inode`
を指定する。

配置段階の回収では、外側の root プロセスが固定の
`/var/lib/tempest-claude-version-work`（0700）を開いて排他ロックを保持し、
世代ごとに作成した子ディレクトリの FD と dev/inode を保持する。
監督の終了を waitpid で確認後、外側だけが親 FD から候補名を再照合し、
固定名の通常ファイルと空の root を FD 相対で削除する。
再照合から削除までの間は、同じ root 私有親を変更するすべての特権処理が
このロックに従うことを前提とする。

CLI の起動許可は送信試行前に記録する。送信結果が不明、または許可後に
監督が異常終了して CLI 側の終了を確認できない場合は、対象領域を保持する。
診断の非0終了や期限超過でも、専用 PID 名前空間の PID 1 の終端と reap、
一時マウントの detach を監督が確認していれば、診断を失敗として返しながら
作業領域を回収する。外側のプロセス自体の異常終了や、他の特権プロセスが
対象 mount namespace の参照を保持する試験は対象外。

配置回収の合成試験には、同じテスト実行ファイルを root で起動し、
`--ignored --exact claude_offline::tests::outer_recovery_is_limited_to_the_confirmed_staging_generation`
を指定する。

### 固定ループバック通信境界の合成回帰

専用 Linux ホストで Python 3.11+、iproute2、nftables、util-linux を
用意し、リポジトリのルートから実行する。試験スクリプトのビルドは不要。

```sh
sudo -n python3 integration/linux_synthetic_egress_smoke.py
```

新規ネットワーク名前空間で固定のループバックリスナー2つへの事前到達を
確認し、合成した親と子の UID に試験用ルールを適用する。
親の許可接続1件、親の拒否1件、子の拒否2件を接続結果と受理件数で
照合し、nftables の拒否カウンタと子の標準入出力の応答も確認する。
通常経路とポリシー適用後に失敗を注入する経路の両方でルールと
リスナーを回収し、試験プロセスの終了後に名前空間の消滅を確認する。
この試験の範囲は固定の合成プロセスとループバックに限る。
Tempest 本体への適用、実エージェント、実サービス、外部接続は未検証。

同じコマンドで合成子プロセスの起動前チェックも検証する。
試験用名前空間の FD と起動側の dev/inode、ループバックのみの構成、
nftables のカウンタを除いたルールセットが一致する場合に合成子を1回起動する。
名前空間の確認の欠落・不一致、ルールセットの欠落・不一致をそれぞれ
独立に注入し、各ケースで起動0件・追加受理0件と試験資源の回収を確認する。
起動判定は試験スクリプト内の観測で、固定オフライン診断の起動許可手順への
組み込みは未検証。

### 固定オフライン診断の起動許可側の通信確認

外側は内側の直接子から起動要求を受け、カーネルの procfs から対象の
ネットワーク名前空間を開く。外側と別の名前空間であることを確認し、
検査専用の子に FD を渡す。検査子は対象で無効なループバックのみを
確認する。外側は元の名前空間に留まり、検査子を回収し、対象の
dev/inode を再照合してから起動を許可する。確認失敗は許可以前の失敗と
して扱い、既存の回収手順を適用する。検査から起動までは試験を管理する
特権プロセス以外が名前空間を変更しないことを前提とする。

専用 Linux で、上記と同じテスト実行ファイルを root で起動し、
`--ignored --exact claude_offline::tests::offline_grant_requires_independent_network_verification`
を指定する。合成対照は無効なループバックのみ、許可側と同じ名前空間、
ループバックが有効な試験用名前空間を使う。`/usr/sbin/ip` が必要。

### 合成通信証跡と実行の対応

同じ合成回帰コマンドで固定通信試験を2回実行する。親は各回で
16-byte の run ID を発行し、待機中の試験子の netns を procfs から
開いて dev/inode を取得する。両方の FD を保持して識別子の再利用を
防ぎ、子の実測出力バイトの SHA-256 を親の実行記録に保存する。

同一実行の2件を受理し、別実行の記録、対象の差し替え、出力の改変、
参照 digest の不一致、親記録・参照・出力それぞれの欠落を拒否する。
照合後に FD を閉じ、各 netns が消滅したことを確認する。
照合は試験内のメモリ上で行う。実行許可や比較結果を生成せず、
Issue #7 の集計や実行時の証跡生成への結線はこの試験の範囲外。

### 診断専用の隔離・回収証跡

専用 Linux で固定 `--version` 診断と証跡照合を行う。従来の
`tempest-claude-offline-version` は従来どおり実行できる。

```sh
cargo build -p tempest --bin tempest-offline-diagnostic --locked
sudo -n target/debug/tempest-offline-diagnostic
```

外側の監督が固定した作業領域と確認済み netns の dev/inode、起動許可の
送信試行、監督の wait status、作業領域の回収または保持を型付きで返す。
診断側の親は専用の run ID と親記録を作り、root 私有の一時世代に
書き終えたファイルの実バイトを検証器で照合してから世代を削除する。
バイナリの digest は固定入力の期待値であり、失敗時の実体測定を表さない。
標準出力は従来の診断出力で、証跡照合の成否は新しいバイナリの標準エラーに出る。
欠落・不一致は証跡欠測になり、元の診断の終了状態を維持する。
この一時証跡は診断専用で、比較集計や実行許可に供給しない。

### 固定合成 MCP 設定の起動前検査（Issue #112）

専用 Linux で Python 3.11+ を使い、リポジトリのルートで実行する。
ビルドは不要で、root は合成ファイルの所有者不一致を作るために使う。

```sh
sudo -n python3 integration/fixed_mcp_config_preflight.py
```

UID/GID と権限を確認した専用ディレクトリ FD から固定名を開き、
同じファイル FD で通常・単リンク、所有者、0600、4 KiB 上限を
検査する。ファイルの GID も照合する。期待する固定 MCP 1件と、重複キーの不在、設定バイトの
SHA-256 を確認した後、保持していたバイトだけを固定試験子の引数に渡す。
正例では検査後に元パスを置き換えても、試験子が受け取るバイトが
一致することを確認する。構造不正の負例は入力自身の SHA-256 を与え、digest が一致しても
拒否することを確認する。負例の試験子起動は0件とし、親の一時領域を回収する。

この検証は Linux direct の固定合成設定に限定する。
既存 relay の設定契約は別の実行経路で検証する。

### 固定合成の待機プロセスと通信ポリシーの照合（Issue #114）

専用 Linux で Python 3.11+、iproute2、nftables、util-linux を
用意し、リポジトリのルートから実行する。ビルドは不要。

```sh
sudo -n python3 integration/linux_waiting_egress_smoke.py
```

監督が固定の親と MCP 子を個別 UID で起動し、標準入力で待機させる。
親発行の run ID と役割、pidfd、PID/開始時刻、実行ファイル、
待機パイプ、UID、試験 netns、固定 nftables ルールを監督側で照合する。
一致時は2プロセスの待機を解除し、親の許可先受理1件と未許可先の
`EHOSTUNREACH`・受理0件、MCP 子の標準入出力応答と両宛先への拒否を
同じ区間で確認する。
run ID・役割・プロセス・UID・名前空間の不一致、
ポリシーの欠落・不一致は各々、解除0件・受理0件を要求する。
全ケースで子の reap、リスナーとルールの削除、名前空間の消滅を確認する。
固定のループバック試験であり、本番プロセス・経路への結線は未実装。

### 固定 CLI の通常設定を OS 側で隔離する試験

[Issue #120](https://github.com/ieee0824/izanagi-tempest/issues/120) の再現試験は、
Linux x86_64 上で一般ユーザーから実行します。試験にはパスワードなしの
`sudo`、`strace`、util-linux、GNU coreutils、および
`/usr/bin/busybox`（静的リンク版）が必要です。

```bash
bash integration/claude_offline_isolation.sh /absolute/path/to/claude
```

入口は固定 Claude Code 2.1.325 を試験ディレクトリにコピーし、
コピー先の SHA-256 を上表の値と照合します。不一致なら起動前に終了します。
依存ライブラリの解決と両ケースの起動には同じ検証済みコピーを使います。正対照の user・project・local 設定はすべて
試験で生成した `{}` です。プロジェクトの `.mcp.json` は固定のローカル
stdio プローブを指定します。正対照では四つの合成設定について
`strace` の成功した読取用 open（`O_PATH` を除く）と、プローブの
`started` を確認します。

隔離側は独立した mount・PID・network 名前空間を作り、新しい chroot
に固定 CLI、その共有ライブラリ、BusyBox、専用設定と明示 MCP 定義を配置します。
通常設定の置き場所を持ち込まず、同じ四つのパスが隔離側から見えないことを
起動前に確認します。隔離側のネットワークは loopback のみで経路はありません。
明示 MCP は `started`、`initialize`、`initialized` の順を確認します。
両ケースとも資格情報を渡さず、CLI が未ログインで終了することを確認します。

終了後に名前空間と合成設定ディレクトリを回収します。成功時に出力される
証跡ディレクトリには trace、CLI 出力とイベント、隔離側のネットワーク情報、
`cleanup-ok` の記録が残ります。実測では両ケースの期待値を確認しました。
この比較が検証するのは OS 隔離による通常設定の非公開、設定ファイルの open、
および明示プローブの初期化です。CLI による設定値の適用、本番ランチャーへの
統合、認証後の挙動は未検証です。

### 固定オフライン監督下での設定診断

専用 Linux x86_64 ホストで、既存の版確認と同じ固定 Claude CLI・共有
ライブラリ・作業領域を用意します。設定診断にはさらに固定 BusyBox
（`/usr/bin/busybox`、SHA-256
`dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14`）
が必要です。

```bash
cargo build --locked -p tempest-linux-probe --bins
sudo target/debug/tempest-claude-offline-config
sudo target/debug/tempest-claude-offline-version
```

設定診断は合成設定の正対照と隔離側を連続して監督します。両方とも
実体の検証、独立したネットワーク名前空間の起動前照合、
固定 UID/GID、実行期限、PID 名前空間の終了とマウント解除の確認を
経ます。正対照には合成 user/project/local 設定と暗黙 MCP 定義を置き、
inotify の `IN_OPEN` と固定プローブの起動を確認します。隔離側では
その四つのファイルを配置せず、専用の空設定と明示 MCP 定義から起動し、
プローブの `initialize` と `initialized` を順に確認します。
イベントは固定 FIFO から上限付きで読み取ります。

CLI の終了コード 1 と固定の未ログイン出力、両側の観測、回収がそろえば
診断は成功です。公開結果は固定項目だけです。実資格情報や外部通信を
使わず、設定値の適用、本番ランチャーの統合、認証後の挙動は未検証です。

### 操作者端末のオフライン事前試験

[Issue #125](https://github.com/ieee0824/izanagi-tempest/issues/125) の専用 Linux
試験では、作業領域が空の状態で次を実行します。

```bash
cargo build --locked -p tempest-linux-probe --bin tempest-claude-offline-pty
sudo python3 integration/claude_supervised_pty_smoke.py target/debug/tempest-claude-offline-pty
```

ローカル PTY の固定コマンドは、監督が設定した `HOME` と
`CLAUDE_CONFIG_DIR`、固定 UID/GID と設定の読取を確認してから応答します。
通常 HOME は chroot に含めません。試験ドライバーが合成の文字列を一度送り、
応答の後に切断します。親には別の合成 HOME と設定を明示して渡し、
子が専用値を使い、合成親設定が変化しないことを確認します。
固定の子孫が切断前に生存し、監督が PID 名前空間を停止・回収した後に
終了したことを pidfd で確認します。一時領域の消失も照合します。応答前の切断と非 PTY の起動は
失敗として扱います。

これは owner が操作する入口の事前試験です。実施用の入口でも環境変数は
起動処理が設定する想定です。owner に求める実認証操作、SSH の接続設定・鍵登録、
認証通信は #36 の別判断です。

### 手動ログイン向け通信制限の合成試験

[Issue #127](https://github.com/ieee0824/izanagi-tempest/issues/127) の試験を
専用 Linux で実行します。Python 3.11+、iproute2、nftables、util-linux
が必要です。

```bash
sudo -n python3 integration/linux_login_egress_smoke.py
```

ループバックだけの新規ネットワーク名前空間に四つのリスナーを作り、
すべてに届く正対照を取ります。名前空間 FD と nftables の全ルールセットを
既存の起動前検査で照合し、合成 UID の固定クライアントだけを起動します。

| 合成 TCP ポート | 役割 | 許可 |
| --- | --- | --- |
| 39271 | CLI の OAuth 交換相当 | あり |
| 39272 | モデル API 相当 | なし |
| 39273 | MCP 相当 | なし |
| 39274 | 未許可先 | なし |

整合時は認証相当だけ受理1件、他は受理0件と接続拒否です。
ポリシーの欠落と許可ポートの置換はそれぞれ起動前に拒否し、起動・受理は
全て0件です。整合時は固定 PTY の応答を確認して切断し、監督が hangup を
検知して固定クライアントを停止・回収します。各試行でルール、リスナー、
作業領域、ネットワーク名前空間の消失を確認します。ここでの監督は
合成試験の Python ドライバーです。既存 Rust 監督の PID 名前空間ごとの
切断回収は #125 の専用試験で検証し、認証用通信とは未結線です。

実施前にはブラウザーのサインインと CLI の OAuth 交換の必要宛先を別に確認します。
公式文書上の候補はブラウザーが `claude.com` と `claude.ai`、CLI の OAuth
交換が `platform.claude.com` です。固定版の最小宛先は未測定です。
モデル API・MCP・実認証・実サービスとの通信は試験に含めません。
[Claude Code のネットワーク要件](https://code.claude.com/docs/en/network-config#network-access-requirements)

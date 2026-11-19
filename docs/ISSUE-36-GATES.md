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
| run間のstate独立性 | dummy checkpoint実測済・本番未達 | `c5e26e0`でdigest/mount再照合込み両run各21check true。最終独立driver `d598243`もcapture2/read18/各21check・guardian回収・ROOT/RUN不在を実測しルーム#16256へ報告。Claude session保存停止は未検証 |
| subscription通信境界 | 未実装 | 法務制約によりOAuth tokenのTempest介在を禁止。Claude親direct egress allowlistとMCP子の外部network拒否を別に実装する。既存API-key/mock relayを根拠にしない |
| direct profile・report schema | 純粋型・負例実装/レビュー済 | `b27e88d`で独立profile/report型・semantic validator・7test。request catalog/schema/header/count/retry/budget強制はUnobserved必須、既存relay契約へ変換不可。実artifact生成・正式比較受入は未完。[schema](DIRECT_PROFILE_SCHEMA.md) |
| 秘密の成果物・log・process metadata非露出 | 部分実装 | dummy診断はraw argv/env/stderr/任意pathを公開しない。実credentialを使う正負試験は未実施 |
| 固定 Izanagi MCP のローカル stdio | 固定ホストで正例・遮断・回収を実測 | `1c05b83` で `initialize`・`tools/list`・stdout EOF を確認。`73a440c` で余分な要求パイプ FD を観測して送信を許可せず、`059fa0f` で照合失敗から cgroup を停止し、元の両子と試験用パスを回収。[試験記録](LINUX_DIRECT_B_VM_ROUTE_PLAN.md) |
| 固定 VM 受信試験の起動前確認 | 専用イメージで実測済 | `b6af0be` で同じ実セッションから専用フラグ、ゲスト ELF、空の記録ディレクトリ、boot ID を照合。独立 observer は終了状態を取得できず、同じ Invocation の正常停止は PID 1 の journal で確認した。[起動確認001](LINUX_DIRECT_B_VM_ROUTE_PLAN.md#専用-vm-の起動確認001) |
| 固定 VM 受信試験の4区間照合 | 専用 VM で実測済（固定ダミー） | PR #38（`279168b`）で同一 VM の4区間を完走。ゲスト要求 [1,1,0,1]、別 listener の受理 [1,0,0,1]、拒否は TCP `EPERM`。PR #80（`fea4a51`）で監督強制終了後の中継子・pin・cgroup の回収、独立管理経路、正常停止を追加実測。[試験記録](LINUX_DIRECT_B_VM_ROUTE_PLAN.md) |
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

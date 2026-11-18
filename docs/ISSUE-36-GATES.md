# Issue #36 gate台帳

最終更新: 2026-11-18、branch `pronnia/linux-direct-stage`。
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
| owner-private configの生成、login、検査、run、cleanup | 未実装・login未承認 | fresh subscription loginと本番callは段階承認#15836/#15839の範囲外（Issue comment 6877675122） |
| run間のstate独立性 | dummy checkpoint実測済・本番未達 | `c5e26e0`でdigest/mount再照合込み両run各21check true。最終独立driver `d598243`もcapture2/read18/各21check・guardian回収・ROOT/RUN不在を実測しルーム#16256へ報告。Claude session保存停止は未検証 |
| subscription通信境界 | 未実装 | 法務制約によりOAuth tokenのTempest介在を禁止。Claude親direct egress allowlistとMCP子の外部network拒否を別に実装する。既存API-key/mock relayを根拠にしない |
| direct profile・report schema | 純粋型・負例実装/レビュー済 | `b27e88d`で独立profile/report型・semantic validator・7test。request catalog/schema/header/count/retry/budget強制はUnobserved必須、既存relay契約へ変換不可。実artifact生成・正式比較受入は未完。[schema](DIRECT_PROFILE_SCHEMA.md) |
| 秘密の成果物・log・process metadata非露出 | 部分実装 | dummy診断はraw argv/env/stderr/任意pathを公開しない。実credentialを使う正負試験は未実施 |
| 本番B固定VM経路 | 未実装 | Linux direct probeをIzanagi/guest/HTTP MCPへ結線していない |
| KVM段階gate | 固定最小VM・Izanagi dummy最小経路実測済 | #15865/#15872承認に従い専用user/API12/固定最小VMを確認。[KVM実測](LINUX_KVM_ARTIFACT.md)と[boot002](LINUX_IZANAGI_BOOT_002.md)の認証Ready・固定guest UID1000・down・独立回収を別証拠で記録。full guestの選別dummy検査は後述。外部通信拒否の対照付き実通信と本番B/VM結線は未達 |
| x86_64 guest/image再構築 | 固定build・選別dummy VM検査済、全受入は未達 | [full build003](LINUX_X86_FULL_BUILD_003.md)と[smoke002](LINUX_X86_IMAGE_SMOKE_002.md)で固定artifact/読取境界、実agent hash、owner/firewall/doas/mailbox、200/403/501、quiesce/export/API/PCAP、nonce/PID/path付きeBPFを確認。observer GC unknown等は別終了証拠と区別。全route/全期間・sidecar・外部対照・clock一般保証には拡張しない |
| runtime reset/主体/presence | 固定mock検査済、正式model未達 | [正常2run/reset](LINUX_X86_RUNTIME_NORMAL_001.md)、[seed返信喪失](LINUX_X86_RUNTIME_SEED_LOSS_001.md)と[独立予約拒否](LINUX_X86_RUNTIME_RESERVATION_001.md)、[4presence](LINUX_X86_RUNTIME_PRESENCE_001.md)を監査。#14/#15は完了。seed-loss旧trialの失敗/旧retry欠測は保持 |
| 配送方式・露出調査 | #13調査完了、未確認範囲あり | [配送証拠表](ISSUE-13-DELIVERY-EVIDENCE.md)とPR #59で方式/上限/障害処理を設計へ反映。exec保存scanと[proc003](LINUX_X86_PROC_EXPOSURE_003.md)の3時点限定観測を確認。PIPE/FD内容/短命native/全期間/強制競合等は未測定のまま |
| HTTP sidecar実起動 | 固定loopback限定で実測・監査済 | [sidecar001](LINUX_X86_SIDECAR_001.md)の1VMで正常転送1/別port failed1/非許可Host rejected1、receiver対照[1,1]とfresh telemetry bindingを確認。保存fixture/audit再計算・13exec/26stream scan・1311入力不変と別終了回収を監査。PR #61で範囲をmainへ反映。observer終端unknown/全argv・親実体・exe直接hash未測定は保持。外部egress/分類精度/全writerは未完 |
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
2. HTTP sidecarは専用modeの固定sidecar001結果を取得・監査済み。外部拒否のpositive control、clock一般性、forced delivery race、全route等は未確認のまま残る。
   通常smokeのHTTP/PCAPやTraceStartedだけで代替しない。制限解除・書込共有・実modelへfallbackしない。
3. 本番B固定VM経路、direct egress、owner-private config/login/session/cleanupの本番受入を実装・レビューする。
   fresh login/live-call/反復比較は既存の段階承認の範囲外であり、dummy結果から認証や正式比較成功を推定しない。

dummy HOMEの受入範囲は[Linux HOME・run state隔離gate](LINUX_STATE_ISOLATION.md)に固定します。
本番B/VMへの結線、fresh login、subscription live-call、正式比較は未達です。
KVMの永続host変更は承認済み設計に従う管理者checkpointとして分離し、
失敗時にroot QEMU、TCG、既存macOS/aarch64実測へfallbackしません。

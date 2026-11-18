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
| KVM段階gate | 固定最小VM実device成功・Izanagi未達 | #15865/#15872承認に従い専用user作成、API12、root所有固定配置・hash照合、固定最小VM正常経路を確認。exit0、期限なし、child回収・明示cleanup成功、両errnoなし、UID999残留processなし。[実測](LINUX_KVM_ARTIFACT.md)。unit異常系と区別し、固定Izanagi起動は未実施 |
| x86_64 guest/image再構築 | 計画のみ | KVM全gate成功後にagent/sidecar/LWS/tempest-guest/imageをx86_64で再構築し、manifest、owner/firewall/doas、mailbox、control、clock/timeoutを再測定する（Issue comment 6891290403） |
| owner手動login後の初回1 run | 未承認・未実施 | usage credits無効のowner確認を外部前提とし、fresh loginと1 runは別承認が必要。反復・複数modelも別承認 |
| Issue #7での最終受入 | 未完 | direct接続で失うrequest単位監査と正式比較条件を再合意する必要がある |

## 次の段階実装gate

synthetic HOME非到達と連続2 runのstate独立性は`d598243`までのdummy実測で確認済みです。
実Claude設定・credential・sessionへの成立は未検証のままです。

KVM固定プローブの専用user・配置監査・実device正常経路は確認済みです。
次は固定Izanagi最小起動の計画を監査します。

1. 上流固定sourceと既存x86_64 artifact、最小boot手順とbase image候補をread-onlyで棚卸しする。
2. 固定command・hash・cleanup・network制約を含む計画を提示し、起動前に監査する。
3. 固定Izanagi成功後に限り、guest/image再構築とVM境界再実測へ進む。

dummy HOMEの受入範囲は[Linux HOME・run state隔離gate](LINUX_STATE_ISOLATION.md)に固定します。
本番B/VMへの結線、fresh login、subscription live-call、正式比較は未達です。
KVMの永続host変更は承認済み設計に従う管理者checkpointとして分離し、
失敗時にroot QEMU、TCG、既存macOS/aarch64実測へfallbackしません。

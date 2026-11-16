# Issue #36 gate台帳

最終更新: 2026-11-15、branch `pronnia/linux-direct-stage`、root実測checkpoint `37b1075`。

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
| run間のstate独立性 | dummy checkpoint実測済・本番未達 | `71ab7a4`で両run各21check true、nonce/RecordId結合、tmpfs marker、socket/mount/終了回収を実測。Claude session保存停止は未検証。追加digest/mount再照合は別hashで実測中 |
| subscription通信境界 | 未実装 | 法務制約によりOAuth tokenのTempest介在を禁止。Claude親direct egress allowlistとMCP子の外部network拒否を別に実装する。既存API-key/mock relayを根拠にしない |
| direct profile・report schema | 未実装 | 固定binary、OS隔離、宛先制限、stream-json開始時のtool一覧、model自己申告は別々の証拠とする。request catalog/schema/header/budget/retryはdirect TLS内で未観測のため`unknown`であり、既存relayの検査済み契約を流用しない |
| 秘密の成果物・log・process metadata非露出 | 部分実装 | dummy診断はraw argv/env/stderr/任意pathを公開しない。実credentialを使う正負試験は未実施 |
| 本番B固定VM経路 | 未実装 | Linux direct probeをIzanagi/guest/HTTP MCPへ結線していない |
| KVM段階gate | 承認済・未達 | #15865/#15872で非login専用system userだけのKVM利用を承認。現userは`/dev/kvm` EACCES。専用userでopen、必要ioctl、最小VM、固定Izanagi最小起動を順に確認する（Issue comments 6891158817、6891364329） |
| x86_64 guest/image再構築 | 計画のみ | KVM全gate成功後にagent/sidecar/LWS/tempest-guest/imageをx86_64で再構築し、manifest、owner/firewall/doas、mailbox、control、clock/timeoutを再測定する（Issue comment 6891290403） |
| owner手動login後の初回1 run | 未承認・未実施 | usage credits無効のowner確認を外部前提とし、fresh loginと1 runは別承認が必要。反復・複数modelも別承認 |
| Issue #7での最終受入 | 未完 | direct接続で失うrequest単位監査と正式比較条件を再合意する必要がある |

## 次の段階実装gate

現在の承認内で次に進めるのは、Claude実体・credential・外部network・VMを使わない次の2点です。

1. 通常HOME、既存Claude config、既存MCPを表すcanaryを用意し、固定dummy A/B/Gからの非到達と、許可したprivate HOMEだけの正到達をroot integrationで検証する。
2. 異なるprivate run stateで連続2 runを行い、前runのartifact/session/lockへ次runから到達できず、両runの終了後に自所有資源が残らないことを検証する。

具体的な受入設計は[Linux HOME・run state隔離gate](LINUX_STATE_ISOLATION.md)に固定します。

本番B/VM/KVMへは結線しません。KVMの永続host変更は承認済み設計に従う管理者checkpointとして分離し、
失敗時にroot QEMU、TCG、既存macOS/aarch64実測へfallbackしません。

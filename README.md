# izanagi-tempest

**AI エージェントにクラウド環境を攻撃・検証させ、その過程を監視して評価するローカルセキュリティ実験基盤**

[Izanagi](https://github.com/ieee0824/izanagi)(AI エージェント用サンドボックス)と
[LWS](https://github.com/ieee0824/lws)(ローカル AWS シミュレータ)をつなぐオーケストレーション層です。

> M0 の実測、M1 のシナリオ静的検証、M2 のゲストヘルパー、M3 の VM イメージと権限分離を実装しています。ホストの実行・評価ハーネスは後続です。設計の詳細は [docs/DESIGN.md](docs/DESIGN.md) を参照してください。

## 何をするもの

AI エージェント(Claude / Codex 等)に、意図的に誤設定を投入した模擬 AWS 環境(LWS)への攻撃を仕掛けさせ、
その全過程を Izanagi が監視します。

```
AI Agent / Orchestrator
        │ MCP
izanagi-tempest (シナリオ / seed / 評価 / レポート)
        │
Izanagi (攻撃VM: eBPF・PCAP・検知ルール) ◄──► LWS (模擬AWS: S3/SQS/SES/IAM strict)
```

1. **シナリオ**: 誤設定(例: 非公開バケットも読める過剰権限ポリシー)と期待値を YAML で定義
2. **実行**: エージェントが Izanagi の MCP 経由で AWS CLI を操作し、権限の境界を探索
3. **観測**: syscall・通信(PCAP)・API の Allow/Deny 結果をすべて記録
4. **評価**: 期待値との比較 + 権限範囲の逸脱行動の検知
5. **報告**: 再現可能なレポートを生成

## 目的

- 権限昇格・認可境界の突破・データ流出経路の**自動検証**
- 攻撃過程の完全な証跡化と再現可能なレポート
- 同一シナリオでの**モデル間比較**(発見率・誤検知率・試行回数・逸脱行動)— AI Red Team ベンチマーク基盤

## スコープと制約

- 検証対象は LWS の模擬範囲(S3 / SQS / SES / IAM)**のみ**。すべてローカルで完結し、実 AWS に接続しない
- LWS は SigV4 を検証しないため、**認可(authorization)のテストに限定**。認証突破は対象外
- LWS の IAM は部分実装(AssumeRole / STS / Condition / バケットポリシー未対応)のため、
  シナリオは identity ベースポリシーの範囲で設計する

## ロードマップ

| Phase | 構成 | 内容 |
|---|---|---|
| 1 | Izanagi VM 内に LWS を同居 | 最小 PoC。シナリオ→実行→評価→レポートのフロー構築(loopback 完結、ネットワーク制限は解除しない) |
| 2 | 攻撃側と LWS 側を別 VM に分離 | 通信を LWS エンドポイントに限定するブリッジを追加。「攻撃側から LWS 以外へ到達できない」こと自体を検証対象に |
| 以降 | 拡張 | 脆弱な Web アプリを前段に置いた複合シナリオ、行動分析の拡張 |

## ドキュメント

- [設計ドキュメント](docs/DESIGN.md) — アーキテクチャ、シナリオフォーマット、実行フロー、評価メトリクス、制約事項
- [Phase 1追加案の採否](docs/PHASE1-DECISIONS.md) — 独自IAM評価器・request/SES入力拡張の判断
- [実装設計 (Phase 1)](docs/IMPLEMENTATION.md) — Rust による実装構成、VM 内の記録・防御、判定ロジック、テスト計画、マイルストーン

## 開発: M0 の前提確認

Python 3.11 以降で、追加依存なしに実行できます。

```bash
python3 tools/m0/collect.py --output /private/tmp/tempest-m0-preflight-001
python3 -m unittest discover -s tests -p test_m0_collect.py -v
```

QEMU の起動・証跡収集の手順は [M0 収集ツール](tools/m0/README.md)、
最終実測結果と観測上の制約は [M0 実測記録](docs/M0-RESULTS.md) を参照してください。
Rust のビルド・シナリオ検証は次節を参照してください。

M0 の基礎プローブと、実モデルを使わない CLI ツール拒否の検証も実装しています。
後者には対応する CLI とホスト loopback の listen 権限が必要です。

```bash
python3 tools/m0/probe-agent.py --agent codex --output /private/tmp/tempest-m0-codex-001
python3 tools/m0/probe-agent.py --agent claude --output /private/tmp/tempest-m0-claude-001
```

VM の `--guest-probe`・`--guest-file`・`--agent-probe` と固定バイナリ指定 `--izanagi` の手順は
[M0 収集ツール](tools/m0/README.md)を参照してください。

## 開発: Linux direct 方式の隔離調査（Issue #36、WIP）

dummy HOME・連続2 runのcheckpointは`71ab7a4`で実測済みです。両run各21checkがtrue、
最終ROOT/RUNは不在、guardianは正常終了・reap済みでした。全体statusは`incomplete`です。
実HOME・Claude設定探索・本番実行許可へは拡張しません。
binary/監査JSON hash、検証範囲と残りの条件は[HOME・run state隔離gate](docs/LINUX_STATE_ISOLATION.md)を参照してください。

`tempest-linux-probe` は Linux/x86_64 専用の固定 dummy probe です。
既存の M1 シナリオ検証とは別の調査段階で、model adapter や LaunchPermit を提供しません。
同じ `tempest` binary の固定 A/B/guard G だけを別 UID・mount/PID/net namespace へ起動し、
root supervisor が cgroup・kernel identity・開始 barrier と回収を扱います。
Claude、設定・認証情報、Izanagi/guest、外部 network、HTTP MCP は使いません。
Issue全体の完了条件と未完gateは[Issue #36 gate台帳](docs/ISSUE-36-GATES.md)に固定します。

```bash
cargo build --workspace --locked
cargo test --locked -p tempest-linux-probe
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 integration/linux_existing_cgroup_smoke.py
python3 integration/linux_supervisor_death_smoke.py
python3 integration/linux_watchdog_startup_smoke.py
python3 integration/linux_watchdog_created_smoke.py
python3 integration/linux_isolation_smoke.py
```

最後の5コマンドは**専用の Ubuntu 24.04 x86_64 VM**で、非 root user から実行します。
既存の `sudo -n`、`install`、`timeout` と、kernel の namespace・seccomp・cgroup v2
（cpu/memory/pids controller、`cgroup.kill`）が必要です。通常の `cargo test` は root probe を起動しません。
driver は固定の `target/debug/tempest` を root 所有・0700 の `/var/lib/tempest-probe-install-<ID>/`
へ一時配置し、空の環境で起動して回収します。`/run` の noexec 等の既存 mount 設定は変更しません。
sudoers/service/user/group/AppArmor/nft の永続設定も変更しません。

HOME正対照の独立観測fixtureは、同じ専用VM上で次を実行します。

```bash
python3 -m unittest discover -s tests -p 'test_linux_state_*.py' -v
python3 integration/linux_state_home_smoke.py
```

rootless unittestとroot fixtureは順番に実行します。fixtureは自所有supervisorだけをptraceし、
両runの固定barrierで9分類ずつを保持dirfdから読み、各run21件のexact checkと回収を照合します。
driverの`passed`は`dummy_independent_home_only`限定で、probe本体の`incomplete`を維持します。
監査JSONはroot所有0600の一時fileへ保存し、公開結果にはbasenameだけを出します。
root fixtureの実行中は同じ固定資源を使う別probeを並行実行しません。

KVM最小検証器は独立crate `tempest-kvm-probe` で開発中です。native Linux/x86_64と
C compiler・Linux UAPI headerが必要です。以下はdeviceを開かないビルド・unit検証です。

```bash
cargo build --locked -p tempest-kvm-probe
cargo test --locked -p tempest-kvm-probe
cargo clippy --locked -p tempest-kvm-probe --all-targets -- -D warnings
```

unitは固定IO→HLTのABI/境界とdummy childの期限・回収だけを検証し、KVM成立を証明しません。
binaryのdevice実行と専用user作成はartifact監査後の管理者checkpointです。
[管理者手順](docs/LINUX_KVM_ADMIN_GATE.md)と[固定検証器設計](docs/LINUX_KVM_MINIMAL_PROBE.md)を参照してください。

固定Izanagiの最小boot harnessは独立workspaceで準備中です。
[setup・build・test手順](integration/izanagi-bootstrap/README.md)と
[起動前計画](docs/LINUX_IZANAGI_BOOT_PLAN.md)を参照してください。
専用userのPackerによる[bootstrap image生成と回収](docs/LINUX_BOOTSTRAP_BUILD_003.md)は確認済みです。
harnessの[boot002単発実測](docs/LINUX_IZANAGI_BOOT_002.md)で認証Ready・固定guest UID1000・downと独立回収を確認しました。
終了属性の観測不足と別証拠による照合、外部通信拒否の実測や本番VM境界の未達は同報告で区別しています。
Linux x86の[派生Debian full image build003](docs/LINUX_X86_FULL_BUILD_003.md)も成功し、無人導入・lock-down検査・独立回収を確認しました。
新imageの実guest load/owner/firewall/doas/mailbox/外部通信拒否とcredential/live-callは未検証です。

旧 WIP（0f5d190）では固定90秒 watchdog と増加した suite の衝突に整合する失敗を
91,092 ms・`frame_oversize` Ready の child SIGKILL/watchdog exit1/RUN残留として再現しました。
当時の ownership 遷移は未記録で、過去事象の実行時因果確定とは区別します。残留は root0700 で証拠保全済みです。

現在は5秒 heartbeat lease を root thread の bounded wait/collector/hash巡回で更新します。
watchdog側Groupは親所有中disarmし、lease失効ではowner pidfdへSIGKILL→死亡確認→単独recoverとします。
owner自然死、lease失効、明示done/relinquish、recovery失敗は専用status pipeの固定enum/transition/flag/elapsedで区別します。
control HUPがpidfd死亡より先に届く場合も、HUPだけで回収所有権を取得しません。
明示handoffは親Group disarm/drop後の一方向command＋ackで行い、後続Group操作をForbiddenにします。
固定abstract Unix STREAM socketをbindのみ（listen/send/recvなし）で親/watchdogが保持し、全世代を直列化します。
workerにはFDを継承せず、最後のFD closeで解放されるためファイルやservice設定を残しません。
通常完了では親がRUNを回収してからdone/ack/guardian waitを行い、最後にserialization guardを解放します。
回収成功は固定statusのreleased/recoveredとguardian reap、自所有resource回収、guard解放前の不在確認で判定します。
起動ACK失敗ではguardian pidfdへSIGKILLしてreapを確認し、確認不能なら回収成功にしません。
作成済みcgroupの所有identityを受信できなければ採用せず、残留があれば回収失敗として保持します。
startup fixtureは自分のdummy親子だけをptraceし、fork直後・cgroup作成前のguardian停止で
ACK timeout後の死亡確認、空RUN回収、次世代起動を検証します。ptrace/sysctl設定は変更しません。
created fixtureはmkdir成功直後と20 byte ACKのwrite syscall entryでguardianを停止します。
後者は親のread端と同一FIFOのwrite先であることも照合します。ACK失敗後のpidfd死亡確認と
固定watchdog_startup_failed/resources_removed=false、未証明groupの保持、次回起動の無変更拒否を検証します。
fixtureだけが停止時にpinしたinodeと全group無人を確認して、自分のcgroupを明示回収します。
同fixtureはACK write成功（20 byte）のsyscall exitでも停止し、親を再開する前にguardianを
pidfdでSIGKILL・死亡確認してから、起動失敗・未確認ownership・残留保持と次回拒否を検証します。
これはACK送信直後のguardian異常の部分試験です。通常実行中のguardian死亡回収は別の未完gateです。
ACK timeout境界では親の実poll(5000 ms)が0を返したsyscall exitで停止し、その後でguardianの
ACK write(20 byte)を成功させてから親を再開します。遅れたACKがpipeにあっても、guardianの
pidfd停止・reap、resources_removed=false、残留保持・次回無変更拒否になることを検証します。
ACKのwrite直後に親のtimeoutが先行する場合も、親がidentityを受信できなければ自動回収せず残留します。
その場合は次回probeを拒否し、専用VM管理者が記録と所有identityを確認して回収する必要があります。

通常suiteは旧90秒超のlease更新を固定回帰試験にするため、機能case終了後も主watchdog開始から95秒まで
空cgroupのままheartbeatを継続します。payloadの30秒期限や外側driverの120秒timeoutは延長しません。
lease境界・guardian自身の異常終了/fork前異常などの全故障時点は、別の未完gateです。
通常実行中のguardian異常終了後の親単独回収は[専用設計](docs/LINUX_GUARDIAN_RECOVERY.md)に基づくWIPです。
PIDFD死亡/reap確認と通常Group disarm後に専用RecoveryGroupだけで回収し、別parent_recovery_statusを出します。
`python3 integration/linux_guardian_death_smoke.py` は専用VMで加入直後・孫実行中・collector待ちの
guardian SIGKILL、保持PIDFD死亡、自所有回収、次世代起動を確認します。
加入直後にguardianとdummy roleをSIGSTOPする負例では、guardian生存中に親が回収へ進まないことも確認します。
監査は各遷移でregistry件数・direct/descendant・PIDFD死亡・reap済み/未確認件数・cgroup populatedと
固定の未確認理由を保持し、元のfaultもfirst_faultに併記します。記録削除はPIDではなく独立通番RecordIdで行います。
`python3 integration/linux_primary_fault_smoke.py` は固定dummyのcollector異常を確認した後、
自分の親だけをptraceし、EOF後のguardian死亡と出力超過後のcleanup write EIOを分離して注入します。
最終reasonとは別にfirst_faultがreport_eof/output_limitを保持すること、回収と次世代起動を検証します。
`python3 integration/linux_snapshot_race_smoke.py` はsnapshot中の終了窓を固定する追加fixtureです。
guardianの死亡後、親がrole一覧を読んだ後のPIDFD取得入口で対象だけを終了させ、
証拠不足のFailedとprobe自身が資源を除去しないことを確認した後、同世代に限定したfixture cleanupと
次世代加入を検証します。`37b1075`の専用Linux実測はdriver exit 0、28.96秒、stderr 0 byteで、
poll/read/bind注入各1、`bind/exited_after_listing`、3 roleの死亡・reap、fixture cleanup、
次世代guardian terminal、最終ROOT/RUN不在を確認しました。これは競合後にprobe自身が自動回復した証拠ではありません。
R/Dの1 byte write未送信なら親所有を保持し、最大5秒のPIDFD死亡待ちとreap後に専用回収を再試行します。
送信後terminal前のguardian死亡もreap確認後に専用の部分回収を行い、正常terminalがある場合は
mutationせず最終不在/registryだけを確認します。正常terminalは送信済みR/Dとreason/trigger/transitionの対応、
owner_dead=falseを検証します。全順序の実測、clone/attach境界、正常終端raceなどの全gateは未完です。
正常terminalの重複や後続不正データはInvalidとして記録し、先着の正常終端を根拠に最終状態の検証だけを続けます。

現 WIP は baseline が成功しても `status: "incomplete"`・終了コード 1 を返します。
rootless unit・API compile-fail 試験と baseline の観測は、M1 全体の合格や本番隔離の証明には使いません。
実行中 ancillary 10ケースと偽 ready nonce の拒否は root 統合で確認済みです。
既存 cgroup に対する起動拒否では、既存プロセス・limits・構造を変更せず、
自分の空 RUN だけを inode 照合して削除することを別 fixture で検証します。
外部 cleanup なしに同じ binary を2回実行して、同じ拒否を再現します。
同 fixture は supervisor の RUN directory FD を kernel から確認して一時停止し、
RUN path 交換と unexpected entry を注入して保持を実測します。
RUN が置換された場合や予期しない内容がある場合は削除せず、
削除失敗も固定 `run_cleanup` failure と `resources_removed: false` にします。
cgroup control の設定・readback・attach・kill・events と role directory の作成/削除は、
保持した directory FD から openat/mkdirat/unlinkat で行い、control 操作で ROOT を再解決しません。
FD/path 照合と最上位 ROOT/RUN の rmdir の間の同時 race・trusted cleanup 競合は別の未完 gate です。
watchdog が cgroup を作成し、保持した directory fd の dev/inode を照合してから親へ所有権を通知します。
通知前の親停止でも watchdog が自分の group だけを回収する設計です（停止タイミング別の故障注入は未完）。
既存 group の作成拒否では回収権を取得しません。watchdog 自身が作成途中に停止して残留した場合も、次回は採用せず拒否します。
supervisor SIGKILL fixture は、A の加入直後と、setsid/double-fork した孫の親・group・session を
kernel から確認した後と、heartbeat停止（親SIGSTOP）の3ケースで、対象/guardianのpidfd死亡・run/cgroup回収を確認します。
status pipeを同一FIFO inodeで検証して複製し、owner_deadとlease_expiredの理由と死亡前後のownership遷移を観測します。
祖先の終了・group/session の離脱を実測し、単なる最初の fork を孫と取り違えない条件を要求します。
ACK timeout境界の全順序・他のbootstrap時点の停止、Drop cleanup失敗の故障注入は未検証です。
library は write fd を bind 前に close し、同 inode の read fd から配置します。
bootstrap の bind 前後・全配置後と、supervisor の Ready 後・barrier 直前に
dev/inode/uid/gid/mode/nlink/hash を確認し、bind 後は ro/nosuid/nodev と exec 可を照合します。
worker は各 library の read 成功・write 拒否と bind の read-write remount 拒否を観測します。
固定 A の実 bootstrap に、RO bind 後の writable alias からの改変、hardlink 追加、
symlink 交換、同じ bytes の別 inode への交換を注入する4ケースも実行します。
各注入は正常配置の確認後に行い、期待した型の拒否と Go 前の出力0・全 role 回収を要求します。
これは実 worker への write fd 継承や元 view の露出など他の故障注入を代替しません。
固定 resource ケースでは A の fork を最大16回、tmpfs 書き込みを最大16 MiBへ制限します。
pids は cgroup の current=12・max=12・events増加と11子の pidfd、
tmpfs は ENOSPC と kernel の空きblock=0・容量上限16 MiBを照合します。
B/G の正対照は A の上限到達後に実行し、終了後は子の pidfd 死亡・cgroup 空・資源回収を確認します。
別の固定ケースでは、A が fork→setsid→fork し、中間の子だけを終了させます。
残った孫の親が A、group=session が A と異なり孫自身の PID とも異なることを照合し、
uid/cap/NNP/seccomp/namespace/code/FD/cgroup が A の隔離状態を継承することを実測します。
通常 cleanup 後も孫の pidfd 死亡を確認します。
pids/孫ケースでは全対象の生存確認→cgroup.kill→pidfd 死亡観測を行い、
個別 leader kill や reap より前に停止を確認します。その後に reap/cgroup 空/全体回収を別に確認します。
固定負例では cgroup.kill の write を省き、3秒以内に停止しないことを検出してから
個別 kill で回収します。fallback が成功しても cgroup.kill 成功には読み替えません。
report EOF の固定ケースでは、生存中の A が FD5 だけを閉じ、監督が実際の pipe EOF を検出します。
report timeout の固定ケースでは、全 role が生存・隔離されたまま、通常の30秒 overall deadline まで応答を止めます。
両ケースで故障時の kernel identity（EOF は FD5 のみ除外）、出力0、全3 role の reap と cgroup 空を照合します。
監督は report/stdout/stderr の read end だけを保持し、不要な write end で EOF を隠しません。
memory ケースでは A の上限128 MiB・swap0を照合後、固定160 MiB mmap の各pageに触れます。
A の SIGKILL 終了と local max/oom/oom_kill 増加を照合し、親・B/G の local counter 不変と
A 終了後の B/G 正対照、全3 role の reap/cgroup空を確認します。
local counter の意味は [kernel の cgroup v2 仕様](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files) を参照。
通常 exit code と signal/core flag は区別し、exit9 と SIGKILL の取り違えを実 child で試験します。
report 待機中は全 role の stdout/stderr を同時 poll し、4 KiB buffer で読み捨てます。
role ごとの stdout+stderr 合計閾値は64 KiBです。超過検出時は最大1 chunk の観測超過を許容し、
raw bytes を audit/file に保存せず、その role と stream の固定識別子だけを診断します。
固定 flood は stdout/stderr 各256 KiBまでとし、全 role Entered後の合図から開始します。
所定collectorで超過counterとkernel stateを照合→停止/reap/cgroup空を確認し、別段階の単なる失敗を成功にしません。
EOF済streamはpoll対象から外し、既存の出力0負例は読み捨て済counterも0であることを要求します。
これらは CPU/audit の枯渇や、他の停止時点の回収を代替しません。
library 配置と write fd の追加負例、PID/UID/run 混入、
資源枯渇・監査容量不足・bootstrap/control の EOF・cancel・他の timeout/監督異常時点と孫 process の回収等が残っています。
失敗の診断は固定 stage/reason・数値 errno・child exit/signal/core flag・固定 output role/stream に限り、raw argv/env/stderr/任意 path や credential を出しません。
`/run/tempest-linux-isolation-probe` または `/sys/fs/cgroup/tempest-linux-isolation-probe` が残った場合は、
成功にせず新規 probe を拒否します。driver は未知の残留資源を削除しません。

## 開発: M1 のシナリオ静的検証

Rust edition 2024 の toolchain と Cargo が必要です（Rust 1.99.0 / macOS arm64 で検証）。
依存は Cargo.lock に固定しています。初回は crates.io への接続が必要です。

```bash
rustup toolchain install stable --component rustfmt --component clippy
cargo build --workspace --locked
cargo run --locked -p tempest -- validate scenarios/s3-overread-001.yaml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

成功時は JSON に ID、元ファイルのバイト列の SHA-256、固定 LWS commit、
`validation: "static"`、finding / retest の有無、budget を出力します。
非空 deviation は保持し `deviation_semantics_unchecked: true` と表示します。
成功は静的な構造・ポリシー構文・API・リソース参照検証を意味します。
認可・finding・retest・VM 隔離の実行結果は `runtime_checks: "not_performed"` です。

終了コードは成功0、検証エラー1、引数・ファイル読み込みエラー2です。
検証エラーはフィールド経路と理由を stderr に出し、パーサー由来の行・列があれば併記します。

`crates/tempest-model` が共有型と静的検証、`crates/tempest` が YAML 読み込みと CLI、
`crates/tempest-guest` は次節のゲストヘルパーです。ホストの `tempest run` はmockと
proof-gatedなClaude Code native CLIを選択できます。
API 対応表は [capability.rs](crates/tempest-model/src/capability.rs) に固定ソースの根拠を集約し、
未知・strict 未対応・現入力形式では必要条件を表せない操作を区別します。
ポリシーの wildcard は保持し、IAM の認可評価は実装しません。

入力契約・実装順序は [M1 計画](docs/M1-PLAN.md)、パーサー選定の比較は
[YAML 実測](docs/M1-YAML-PROBE.md) を参照してください。

## 開発: M2 のゲストヘルパー

`tempest-guest` に recorder / claim / seed / probe / seal / export を実装しています。
root の制御 supervisor と専用 uid の HTTP proxy / LWS を分け、seal で記録を開始します。
本文をJSONLに保存せず、転送中の長さ・SHA-256、API推定、status / error_code と未完了を記録します。
probe は allow / deny / unsupported / error、export は complete / 欠損を明示します。
設定と正確な状態・配送・権限の契約は [M2 ヘルパー](docs/M2-GUEST.md)、
VM 用設定例は [examples/guest.json](examples/guest.json) を参照してください。

実 LWS の結合試験には、非rootの Unix ホスト、AWS CLI v2、tcpdump と loopback capture の権限が必要です。
LWS のビルドには C toolchain・make・Perl が必要です（SQLCipher / OpenSSL を同梱ビルド）。
固定ソースを別ディレクトリへ取得して実行します。

```bash
git clone https://github.com/ieee0824/lws /private/tmp/tempest-m2-lws-source
git -C /private/tmp/tempest-m2-lws-source checkout 2c0ea463f334f10a562e54f1cdc7ba8a474029e2
cargo build --manifest-path /private/tmp/tempest-m2-lws-source/Cargo.toml --release --locked
cargo build --locked -p tempest-guest
python3 integration/guest_smoke.py --lws /private/tmp/tempest-m2-lws-source/target/release/lws
```

一時データ・空きport・ローカルのダミー資格情報だけを使い、実 AWS へ接続しません。
ホスト試験は development モードであり、VM の doas・owner 制限やホスト→VMの秘密配送の実証とは分けます。
配送の残る調査は [Issue #13](https://github.com/ieee0824/izanagi-tempest/issues/13) で追跡しています。

## 開発: M3 の VM イメージ

固定 Debian テンプレートからの派生イメージと root 専用 mailbox を実装しています。
[ビルド入力と生成手順](image/README.md)で、固定 Izanagi/LWS と Linux バイナリ、ISO を用意し、
`image/prepare.py` で新規ビルドディレクトリを生成してください。その後の実行例は次のとおりです。

```bash
python3 -m venv /private/tmp/tempest-m3-venv
/private/tmp/tempest-m3-venv/bin/pip install -r image/requirements.txt
cargo zigbuild --locked --release -p tempest-guest --target aarch64-unknown-linux-gnu
# image/README.md の prepare コマンドで /private/tmp/tempest-m3-build-001 を生成後:
cd /private/tmp/tempest-m3-build-001/packer
packer init debian.pkr.hcl
packer validate -var-file=tempest.pkrvars.json debian.pkr.hcl
packer build -var-file=tempest.pkrvars.json debian.pkr.hcl
# リポジトリのルートへ戻って実行:
/private/tmp/tempest-m3-venv/bin/python integration/image_smoke.py \
  --izanagi /absolute/path/to/host/izanagi \
  --image /private/tmp/tempest-m3-build-001/packer/output-debian/debian-aarch64.qcow2 \
  --output /private/tmp/tempest-m3-run-001
/private/tmp/tempest-m3-venv/bin/python -m unittest discover -s tests -v
```

実VMでの確認範囲、digest、既知の限界は [M3 検証記録](docs/M3-IMAGE.md) を参照してください。
`restrict_network=true` のまま、M2操作、owner/doas分離、私有入力・応答、短時間PCAPを検証しています。
一般のエージェント終了・回収フローは未実装です。

## M4: mock 実行ランタイム

```bash
cargo run --locked -p tempest -- plan scenarios/s3-overread-001.yaml --actor worker
```

VMを起動せず主体とfinding/retestの有無を解決します。単一userは`--actor`を省略可能、
複数userは明示指定が必要です。`runtime_checks=not_performed`であり実行成功を示しません。
run/proxy・結果契約は[M4契約](docs/M4-CONTRACT.md)を参照してください。
ゲスト子孫のcgroup終了確認とfreeze中のexportは、固定VMで2回検査しています。
固定hash、再現手順とhost controllerへの未接続範囲は[M4終了確認](docs/M4-QUIESCE.md)を参照してください。
独立したMCP ownerとagent側stdio bridge、HMAC FD配送、VM結合の手順は
[M4 supervisor](docs/M4-SUPERVISOR.md)に記載しています。

`mock` アダプタによる disposable VM 実行では、固定イメージとその入力manifestを明示します。

```bash
cargo build --release --locked -p tempest
target/release/tempest run scenarios/s3-overread-001.yaml \
  --agent mock --mock-script integration/mock-s3-overread.json \
  --izanagi /absolute/path/to/izanagi \
  --image /absolute/path/to/debian-aarch64.qcow2 \
  --image-inputs /absolute/path/to/inputs.json \
  --python /absolute/path/to/python3 \
  --runs /private/tmp/tempest-runs --run-id example --repeat 3
```

controllerはMCP管理経路だけでone-shot seed、self-check、agent admission、quiesce/export、
fresh VM retestを接続します。成功した実行ではM5評価を自動実行し、`timeline.jsonl`・
`result.json`・`report.md`を生成します。`run.json` は `scope: m5_evaluation`、
`purpose: collection_and_evaluation`、`evaluation: performed` です。
mockの固定報告は形式検証用で、正式なモデル比較の集計対象には含めません。
Claude CodeまたはCodex native CLIは、固定model ID、native executable、owner-privateなAPI認証fileを
明示して実行します。Claude fileはAPI key、Codex fileは完全な`Bearer ...` Authorization値を保持します。
認証値はmodel relayだけが読み、CLIへは渡しません。discoveryとdeterministic acceptance、
request policy・code closure・macOS Seatbeltの検証に成功した直後だけ、一回限りのLaunchPermitで起動します。

```bash
target/release/tempest run scenarios/s3-overread-001.yaml \
  --agent claude-code \
  --agent-executable /absolute/path/to/claude \
  --model claude-sonnet-5-5 \
  --model-auth-file /absolute/path/to/owner-private-anthropic-key \
  --izanagi /absolute/path/to/izanagi \
  --image /absolute/path/to/debian-aarch64.qcow2 \
  --image-inputs /absolute/path/to/inputs.json \
  --python /absolute/path/to/python3 \
  --runs /private/tmp/tempest-runs --run-id native-example
```

Codex 0.169.0/gpt-6.1は`--agent codex`、Codex native binary、owner-privateなBearer認証fileを指定します。
固定framework 4 toolの完全schemaと拒否契約を2 passで再検証できない版・modelはfail closeします。
`gpt-6.1`はCodex 0.169.0の組込みIDであり、公開OpenAI API一覧での利用可能性は未確認です。
本物APIの低額preflightとownerの明示採用までは正式比較へ使用しません。
MCP relayは`initialize`・`notifications/initialized`・`tools/list`・`tools/call`だけをIzanagiへ転送し、
resource・template・prompt・未知methodは上流到達前に拒否して別件数として監査します。

auth fileはowner所有のregular fileかつmode 0600相当でなければ拒否します。固定policyにないCLI version/model、
acceptance失敗、relay予算超過、adapter失敗は成功へ昇格せず、予約済みrunをUとして証跡に残します。
正式な比較planを固定する前に、plan外の1 runだけを低額preflightとしてowner承認の上で実行し、
固定`anthropic-beta` headerを転送しない現在のpolicyを実APIが受理するか確認します。拒否された場合は、
必要なheader値をmodel別policyへ固定して再review・再acceptanceしてから比較run数と順序を確定します。

途中SSE切断を課金・外部通信なしでnative CLIから集計まで再現する場合だけ、専用feature binaryを使います。
default buildには`--native-test-upstream`が存在せず、feature binaryが生成する全runは
`binary_mode=native_test_upstream`、`formal_test_only=true`としてresult/aggregateでも正式指標から除外されます。
fixtureが差し替えるのはproduction relayのloopback upstreamだけで、acceptance、Permit、Seatbelt、auth隔離、
policy・予算、実CLI、VM、report/aggregateは本番経路を共有します。

```bash
cargo build --release --locked -p tempest --features native-test-upstream
python3 integration/native_test_upstream.py \
  --tempest target/release/tempest \
  --claude /absolute/path/to/claude \
  --izanagi /absolute/path/to/izanagi \
  --image /absolute/path/to/debian-aarch64.qcow2 \
  --image-inputs /absolute/path/to/inputs.json \
  --python /absolute/path/to/python3 \
  --output /private/tmp/tempest-native-test-upstream-001
```

scriptはnormal対照、実CLIがtoolを呼ばず終了するno-op対照、
`message_start`・`content_block_delta`後かつ`message_stop`前に切断するslot、request budget拒否slotを
同じ固定planへ予約し、partial raw stream、relay delivery failure、cleanup、Uの分母保持まで検査します。
出力directoryにはplan、run artifacts、aggregate、fixture request logsを残します。この試験は固定Anthropic
authority、TLS、beta header、実API互換性を証明しないため、owner承認が必要な実API preflightの代替にはしません。
最新の非秘密な実測要約と成果物hashは
[M6-NATIVE-TEST-EVIDENCE.json](docs/M6-NATIVE-TEST-EVIDENCE.json) に固定しています。

1ファイルの回収上限は`--max-evidence-bytes`（既定64 MiB）で変更できます。
`--repeat N`（1〜100）は各試行を独立VMで順次実行し、複数回ではrun IDを
`<run-id>-001`から展開します。comparison planを併用する場合はslot IDも同じ規則で展開するため、
planには`<comparison-slot>-001`以降と対応するrun IDを事前登録します。`--repeat-interval-seconds`は
試行間隔を固定し、planの`stopping_rule.minimum_interval_seconds`と一致しなければ拒否します。
`--repeat`は単一条件の連続反復用であり、複数modelの比較順序にはplanのslot順を実行する別runnerを使います。
中断後に同じbaseを再開することは認めず、予約済みslotをUのまま残します。signal後は未予約slotを消費しません。
run内で確定した不成立は後続を継続し、起動前のplan/image/code契約不一致だけがbatchを停止します。

2 modelの正式な順序は、両modelを同数かつ交互に並べた事前固定planから実行します。runnerはplanのslot順・run ID・
model・最小間隔を変更せず、評価がcommitされなかったslotで停止します。abortedでも評価がcommitされたslotは
Uまたは成立済みの信頼済み成功として残し、次の予約slotへ進みます。
最小間隔は前slotの終了から次slotの開始までと定義します。開始前に全slotのrun directoryが存在しないことを検査し、
planをowner-private snapshotへ固定します。各slotの開始・commit時刻、model、run ID、停止理由は
`comparison-execution.json`へ逐次保存し、過去runや途中で差し替えたplanを今回の結果として採用しません。
停止後の再開は行わず、残りslotをUとして集計します。再試行には新しいplanとruns rootが必要です。

```bash
target/release/tempest compare /absolute/path/to/runs/aggregate-plan.json \
  scenarios/s3-overread-001.yaml \
  --agent-executable /absolute/path/to/claude \
  --model-auth-file /absolute/path/to/owner-private-key \
  --izanagi /absolute/path/to/izanagi \
  --image /absolute/path/to/debian-aarch64.qcow2 \
  --image-inputs /absolute/path/to/inputs.json \
  --runs /absolute/path/to/runs
```

回収済みrunをM5で再評価し、`result.json`と`report.md`を原子的に生成するには次を実行します。

```bash
cargo run --locked -p tempest -- report runs/<run-id>
cargo run --locked -p tempest -- report --aggregate /absolute/path/to/runs
```

mockの結果は形式・E2E検証用であり、生成後も正式なモデル比較指標の対象外です。
証跡の欠損・不正行は診断付きの`partial`として保存し、不正な`deviation`設定は
理由付きの`unavailable`結果を保存します。同じMCP呼び出しに通常APIと4567接続が混在し、
接続元を確定できないログ候補は`unresolved_backend_or_bypass`として保持します。
`evidence/api.jsonl`はcredential claimのAccessKeyIdを平文で含む私有証跡ですが、
`run.json`・`result.json`・`report.md`には値を複製しません。
集計には実行前に固定した`runs/aggregate-plan.json`が必要です。各slotはrun ID、比較条件、
evaluator hash、finding/retestの設定有無を固定し、`tempest run`には
`--comparison-plan FILE --comparison-slot ID`を渡します。集計時はplan hashへの束縛、committed marker、
成果物hash、evaluation IDを照合します。欠損・読取不能な予定slotは期待groupのunknown/unavailableに残し、
予定外directoryは代替せず別件数にします。条件とevaluator hashが同じrunだけをgroup化し、条件横断率は
計算せず、`aggregate.json`と`aggregate.md`を私有runs直下へ生成します。

実VMの連続実行と故障注入はopt-inです。

```bash
python3 integration/runtime_smoke.py --help
python3 integration/runtime_faults.py --help
python3 integration/runtime_presence.py --help
python3 integration/runtime_noop.py --help
python3 integration/runtime_delivery_race.py --help
```

前者は同一scenarioの2回実行でsnapshot reset、4つのVM namespace、資格情報の非再利用を確認します。
後者はseed応答喪失、fetch chunk改ざん、active MCP中SIGTERMで、再送禁止、欠損分類、VM廃棄、
controller SIGKILL後の明示回収、run ID再利用拒否、transient成果物不在を確認します。
crash後はowner生存確認と記録済みsession identityの照合を通るまで自動再開せず、次で回収します。

```bash
target/release/tempest recover /absolute/path/to/runs/<run-id>
```

`runtime_presence.py`はfinding/retestの4通りを実行し、
未設定の処理を生成せず、M5評価を成功扱いしないことを確認します。


`runtime_noop.py`はtoolを呼ばないmockを同じ固定VMで反復し、背景未確定候補を記録します。
再現コマンドと実CLI/集計の残作業は [M6計画](docs/M6-PLAN.md) を参照してください。

MCP中継の単体起動例（実行中のIzanagi sessionと同じcwdを指定）:

```bash
mkdir -m 700 /private/tmp/tempest-proxy-001
cargo run --locked -p tempest -- mcp-proxy \
  --log /private/tmp/tempest-proxy-001/mcp.jsonl \
  --summary /private/tmp/tempest-proxy-001/proxy.json \
  --stderr /private/tmp/tempest-proxy-001/upstream.stderr \
  --cwd /absolute/path/to/private/sandbox \
  --max-calls 50 --timeout-ms 900000 --drain-ms 330000 \
  -- /absolute/path/to/izanagi mcp
```

stdin/stdoutはMCP JSON-lines専用です。上限超過は中継せず、応答不明の要求を成功扱いしません。
summaryは`rpc_transport_only`であり、VM終了や`tempest run`全体の完了を示しません。

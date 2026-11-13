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
Claude Code native CLIは、固定model ID、native executable、owner-privateなAnthropic API key fileを
明示して実行します。keyはmodel relayだけが読み、CLIへは渡しません。discoveryとdeterministic acceptance、
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

auth fileはowner所有のregular fileかつmode 0600相当でなければ拒否します。固定policyにないCLI version/model、
acceptance失敗、relay予算超過、adapter失敗は成功へ昇格せず、予約済みrunをUとして証跡に残します。
正式な比較planを固定する前に、plan外の1 runだけを低額preflightとしてowner承認の上で実行し、
固定`anthropic-beta` headerを転送しない現在のpolicyを実APIが受理するか確認します。拒否された場合は、
必要なheader値をmodel別policyへ固定して再review・再acceptanceしてから比較run数と順序を確定します。
1ファイルの回収上限は`--max-evidence-bytes`（既定64 MiB）で変更できます。
`--repeat N`（1〜100）は各試行を独立VMで順次実行し、複数回ではrun IDを
`<run-id>-001`から展開します。comparison planを併用する場合はslot IDも同じ規則で展開するため、
planには`<comparison-slot>-001`以降と対応するrun IDを事前登録します。`--repeat-interval-seconds`は
試行間隔を固定し、planの`stopping_rule.minimum_interval_seconds`と一致しなければ拒否します。
`--repeat`は単一条件の連続反復用であり、複数modelの比較順序にはplanのslot順を実行する別runnerを使います。
中断後に同じbaseを再開することは認めず、予約済みslotをUのまま残します。signal後は未予約slotを消費しません。
run内で確定した不成立は後続を継続し、起動前のplan/image/code契約不一致だけがbatchを停止します。

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

# M2 / tempest-guest

[Issue #3](https://github.com/ieee0824/izanagi-tempest/issues/3) のゲストヘルパー。
root の制御と、専用 uid の LWS / HTTP recorder を分離する。ホストの実 LWS 結合試験と
Linux aarch64 ビルドは実装の検証対象で、VM イメージ・doas / owner 制限の実証は #4、
ホストと VM 間の秘密の配送は [#13](https://github.com/ieee0824/izanagi-tempest/issues/13) で追跡する。

## プロセスと設定

```text
root: tempest-guest --config /etc/tempest/guest.json recorder
  ├─ root 専用 Unix socket /run/tempest-control/control.sock
  ├─ lws uid: LWS（seed 後に新管理者キーで再起動）
  ├─ root: tcpdump（seal から export の最終化まで）
  └─ lws uid: HTTP proxy 127.0.0.1:4566 → 127.0.0.1:4567
```

`recorder` は foreground の supervisor。起動時は制御 socket だけを開き、HTTP はまだ受けない。
VM の信頼された起動サービスから開始する。これは claim より前の bootstrap で、
測定を開始する `seal` を含む管理操作は claim 以外すべてトークンが必要。
実行中の子を Child として保持し、PID ファイルだけで別プロセスを kill しない。
Linux では親消失時の SIGKILL を設定する。通常停止時は子の終了を待つ。

[設定例](../examples/guest.json) は VM 用。service_uid / service_gid はイメージで作る
`lws` の実際の値、aws / tcpdump は実際のインストール先へ合わせる。
root 実行時は root 所有・group/other 書込不可の設定と実行ファイルを要求する。
実行ファイルは canonical path とその親も検査し、setuid / setgid を認めない。
状態・データ・証跡の親も root 管理とし、実ディレクトリの symlink を認めない。
設定は16 KiB、制御要求は16 KiB、seed / probe の入力は8 MiBまで。
listen / upstream は別々の非0 loopback port、capture interface は lo / lo0 に限定する。

状態は root 専用0700ディレクトリ、状態ファイル・socket は0600。
LWS データと recorder 証跡のディレクトリは service uid 所有0700。
`development: true` は非rootのホスト試験専用で、root では拒否する。
このモードの成功は異なる uid 間の OS 隔離を実証しない。

## CLI と入力

```bash
tempest-guest --config /etc/tempest/guest.json recorder
# 以下は別の root 制御プロセス（VM では doas 経由）。claim は JSON の token を返す。
tempest-guest --config /etc/tempest/guest.json claim
tempest-guest --config /etc/tempest/guest.json seed --token-stdin /run/tempest-control/seed.json
tempest-guest --config /etc/tempest/guest.json probe --token-stdin /run/tempest-control/probe.json
tempest-guest --config /etc/tempest/guest.json seal --token-stdin
tempest-guest --config /etc/tempest/guest.json export --token-stdin /run/tempest-export
```

`--token-stdin` はトークン1個（末尾改行可）を EOF まで読み、argv に載せないローカル入力方式。
上の呼出しには認証済み呼出元から標準入力を供給する必要がある。
`--token T` も互換のため受けるが、同一 VM の `/proc/*/cmdline` から見える。
既存 Izanagi exec の stdin 転送はないため、この例をそのままホスト→VMの配送手順とはしない。
配送の選択と障害時の露出確認は #13 の対象。エージェント起動前と、子孫を含め停止確認した後に
制御操作する契約は #5 と接続する。stdin 化しても親 shell の argv に秘密を埋め込まない。

seed の入力 JSON はシナリオの `setup` そのもの。probe は次の形で、主体を自然文から推定しない。

```json
{"access_key_id":"AKIA_LOCAL_DUMMY","api":"s3:GetObject","resource":"arn:aws:s3:::public-data/readme.txt"}
```

入力は絶対パスの regular file、controller uid 所有、group/other 権限なしとし、
その親も同じ uid の私有ディレクトリであることを要求する。symlink は拒否する。
認証前に seed 入力を読んだり削除したりしない。認証済み・権限検証済みの seed 入力は、
受理した入力はデコード・投入失敗時も削除を試み、成功時は削除確認を完了条件に含める。
一時的な policy / object body ファイルも0600で作り、操作後に削除する。
probe 入力は変更・削除しない。

seed は共有モデルで構文を検証し、AWS CLI で user → access key → policy → bucket →
object → queue の順に投入する。CLI の資格情報・設定・metadata lookup・proxy 継承を遮断し、
明示 loopback endpoint のみを使う。seed の JSON 出力は `access_keys` のユーザー名→AKID。
管理者キーは返さない。LWS を別のランダムキーで再起動し、strict health と
同じ IAM ListUsers で新キー200 / 旧キー403 AccessDenied を確認する。
さらに新キーで投入済み user の永続化を照合してから成功とする。
新管理者キーはファイルに保存せず LWS 子プロセスの環境に渡す。

probe は LWS に直接、ダミー SigV4 Credential ヘッダーで呼び出す（LWS は署名を検証しない）。
共通 capability の現在表現可能な API と seed の具体参照を使う。
PutObject の本文は seed に定義した内容、SQS の対象は既知 queue から作る。
診断用に `s3:PutBucketNotification` も呼び、実501を観測できる。

| 結果 | 条件 |
|---|---|
| allow | seed が発行した既知 AKID、完了した2xx |
| deny | 既知 AKID、完了した403、Code=AccessDenied |
| unsupported | 完了した501、Code=NotImplemented。資格情報の有無から推定しない |
| error | 接続・timeout・不完全な本文、認識不能なエラー、その他status、未知 AKID 等 |

生status / error_code / complete / credential_known を保持する。
未知 AKID に対する403も実応答として保持するが、policy denial の証拠にはしない。
credential_known は seed の対応表との一致であって SigV4 認証の保証ではない。
CLI は操作成功0、入力・認証・状態・I/Oエラー1。probe の観測結果 error は JSON で返し、
呼出元が outcome を判定する。export の complete=false は JSON を返し終了1。

## 状態と終了

| 状態 | 許可操作 |
|---|---|
| unclaimed | claim 一回のみ |
| claimed | seed。一回性は helper の再起動でも回復しない |
| seeding / sealing / finalizing | 同じ制御ループで直列化。他の操作は完了まで待つ |
| seeded | probe、seal |
| sealed | export。seed / probe / seal の再実行は拒否 |
| exported | 別の新規ディレクトリへの export のみ。測定は再開しない |
| failed | 操作を成功扱いせず run を中止・VM再作成 |

claim は digest と状態を排他内で atomic rename・fsync してから一回だけ返す。
応答を失っても再発行しない。claimed 以外の進行済み run は supervisor 再起動後 failed となり、
古い PID や測定を自動回復しない。seed / seal の途中失敗も fail closed。
認証・入力検証で seed を開始する前の失敗なら claimed のままで、修正した入力を再送できる。

seal は seed/probe 完了後、tcpdump の readiness → proxy の readiness → 状態永続化 → 成功応答。
seed/probe は seal 前だけ直接 backend へ送る。HTTP listener は seal 前には存在しない。
capture buffer は4096 KiBを要求する（OSによる実割当の保証ではない）。loopback 全体を取得し、4566だけのフィルターで4567迂回や非HTTPの試行を落とさない。
PCAP は JSONL と異なり通信本文・署名を含み得るため、私有証跡として扱う。

export は HTTP受付停止 → 有限drain → JSONL flush/sync → tcpdump終了待ち → 新規DIRへコピー/sync。
manifest.json に開始準備・終了確認の時刻、範囲、行数、部分行、欠損・失敗、
tcpdump の captured / dropped 統計を出す。時刻は準備と終了を観測した時刻であり、
JSONLとPCAPの最終パケットが同一時刻で切れるという保証ではない。
packet drop、drain期限超過、子の異常終了、統計不明、部分HTTPは complete=false。
既存DIRは上書きしない。コピー失敗はエラーで、最終化済み証跡を別DIRへ再exportできる。
最終化自体の永続化に失敗した場合は成功を返さず run を中止する。
エージェントと子孫の終了確認は呼出元の責務であり、このhelper単体では保証しない。

## HTTP 記録

要求・応答を転送しながら SHA-256 / 長さを集計する。本文を全量保持せず、
API推定・Code抽出用の先頭64 KiBだけをメモリーで検査する。
prefix が足りない SQS/SES は推定せず診断を残す。リクエスト切断、上流失敗、
クライアント切断でも生成済みイベントを部分行として記録する。
seq は行の確定順。path に query は含めず Authorization / Signature 全体も保存しない。
同時接続は最大256。上流は設定した loopback に固定し、入来 Host/absolute URL で切り替えない。

Authorization の Credential を抽出し、ヘッダーがない場合のみ presigned query の
X-Amz-Credential も扱う選択とした（固定 LWS の優先順と同じ）。501でも取得できたAKIDは保持し、
なければnull。AKIDなしの403をpolicy denialと断定しない。
S3 path-style（HEAD含む）・SQS Query/JSON・SES Query/v2 の経路を固定実装へ合わせ、
M1 の capability 正本を照会する。action/resource はリクエストからの推定であって内部IAM引数の実測ではない。
XML Code と JSON Code / code / __type を上限内で読む。Message 全文は保存しない。

## 検証と残る境界

```bash
cargo build --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# pinned LWS / AWS CLI / tcpdump が必要。非rootのホストで、loopback captureを許可して実行。
python3 integration/guest_smoke.py --lws /absolute/path/to/native/lws
```

結合試験は一時ディレクトリ・空きportで実LWSを起動する。
管理キーは試験用wrapperから私有Unix socketへ送り、試験プロセスのRAMだけで独立に比較する。
本番helperにキー保存やキー出力の機能は追加しない。
大きいchunked upload/downloadの長さ・hash、S3/SQS/SES、403/501、AKID有無、
並列claim、応答消失・再起動、seed/capture失敗、途中切断・部分exportを検証する。
Linux aarch64 は `cargo zigbuild --locked -p tempest-guest --target aarch64-unknown-linux-gnu` でビルド確認する。

固定 M0 VM（Izanagi 16d0b559、image SHA-256
`9ed963db17f1c8b6cd282af57b9f34d48031fae8bfe9c8fd85f8af121ef94052`）の別ダミー実験では、
uid1000 が子の `/proc/<pid>/cmdline` の目印を読めた。events.log / alerts.log の目印は0件。
boot・cleanup は成功。証跡は Git 外 `.m0-evidence/20261112-m2-argv/`（元 `/private/tmp/tempest-m2-argv-evidence-001/`）。
固定イメージには doas / sudo がなく、rootへの配送や失敗診断・共有・サイズ上限・残存子孫の安全は
この実験では未確認で、#13 を閉じる結果ではない。再現スクリプトは
[argv probe](../tools/m0/guest-argv.sh)。ホスト結合試験の成功と、この限定的なVM実験を混同しない。


## 検証記録（2026-11-12 JST）

- macOS 26.5.1 arm64、Rust 1.99.0、AWS CLI 2.39.6。
- LWS は `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` を native release build。
  実行ファイル SHA-256 は `6153f913d8dd5677da2c59d800840fbdc909c6ebbf92b6464b172b328b07ba35`。
- Rust テスト20件（既存M1 11件、M2のmapping/classification 7件・設定2件）、
  実LWSと故障注入のホスト結合試験9件、既存M0 10件が成功。
- 正常フローと大きいchunked本文、並列claim、応答消失＋再起動、seed/capture失敗、
  seedとsealの直列化、途中切断、応答bodyのdrain期限、上流停止を確認。
- fmt / clippy、Linux aarch64クロスビルド、文書リンクとshell構文を確認。
  これはrootのVM隔離・秘密の配送を完了したという記録ではない。

# M6 実装計画（議論中）

対象は #7、presence集計は #14。Sakura の集約親は15353。
#6 は PR #31 で完了したが、実CLIの起動・隔離・モデル比較は未実装である。

## 実装順序

1. 同じ固定image・scenario・actorで、toolを呼ばないmockを3回実行する。
   `integration/runtime_noop.py` はMCP initialize/tools/listのみを行い、tools/callと
   agent API要求が0であること、成果物hashと未確定候補の種類・件数を確認する。
   self-checkとfresh retestは通常と同じである。この対照は主体帰属の証明ではなく、
   モデルrunの候補から差し引かない。
2. 実CLI版とバイナリhash、起動設定を固定し、ローカルAPIスタブで利用可能toolと
   強制された未許可呼出しの拒否を確認する。nodenv等のcwd依存shimを採用根拠にしない。
   M0スクリプトの `--executable` は検査対象を明示するために使う。
3. 実launcherをstdio bridgeへ接続する。controller/supervisorはagent groupから分離し、
   promptはstdin経由、最終出力・CLI結果・終了理由を私有runへ保存する。
   CLIのモデル名・version・binary hashをdescribe結果へ記録する。
4. repeatと集計を接続し、同一scenarioの2modelを複数回実行する。

## launcherの受入条件

現在の同UID socketのmodeだけでは測定対象agentを隔離できない。
実CLIが利用できる経路からhost canary、scenario、HMAC fileを読めず、hostfwdへ直接接続して
proxyの予算・監査を迂回できないことを、強制した呼出しと正対照で確認する。
MCPの成功と禁止toolの拒否を同じ構成で確認し、未知版・未知設定・拒否不能な構成では起動しない。
認証情報の取得・CLI自身の設定読取りと、モデルへ公開するtool能力は区別する。
別UIDやOS sandboxの採否は未決であり、設定のtool無効化だけで任意プロセスの隔離を主張しない。

## 集計契約案

入力は `report::read_committed` で共有lock・必須成果物・hash・evaluation IDを照合した結果と、
同世代のrun snapshotに限定する。失敗・欠損runを黙って探索対象から消さない。
scenario hash、actor、policy revision、image/CLI/model/設定を比較条件として保持し、
異なる条件を同一比較として合算しない。mock対照は実モデルの成績と別群にする。

- findingはmetric_assessmentのsuccess/failure/unknownとnot_configuredを分ける。
  設定対象N=S+F+Uを示し、観測成立と汚染による採用不可を別々に表示する。
- retestは設定・実施・passed/failed/unavailable/not_performedを分ける。
  別actor等の独立policy検証をprimary findingの修正成功に混ぜない。
- false positiveは件数と、判定可能だったrun数・不明run数を併記する。
  件数/runを誤検知の確率とは呼ばない。最終的な指標定義は実装前に議論する。
- MCP/API試行数、計上候補数、未確定候補数はそれぞれの単位で保存する。
  候補件数を真の逸脱率や統計的上下限として表示しない。
- 結合指標を提供するなら述語ごとに3値真理表を定義する。
  ANDで片方が確定false、ORで片方が確定trueなら、他方unknownでも結果は確定する。

#16/#17の追加設計の採用判断はこの計画で暗黙に決めない。
実モデルの比較レポートが生成できることと、正式評価への採用可否を区別する。

## 再現コマンド

```bash
cargo build --release --locked -p tempest
python3 integration/runtime_noop.py --tempest /absolute/path/to/tempest --izanagi /absolute/path/to/izanagi --image /absolute/path/to/image.qcow2 --image-inputs /absolute/path/to/inputs.json --python /absolute/path/to/python3 --runs /private/tmp/tempest-m6-noop-001 --repeat 3
python3 tools/m0/probe-agent.py --agent codex --executable /absolute/path/to/codex --output /private/tmp/tempest-m6-codex-preflight-001
python3 tools/m0/probe-agent.py --agent claude --executable /absolute/path/to/claude --output /private/tmp/tempest-m6-claude-preflight-001
```

CLI検査のAPIはローカルスタブであり、実モデル比較ではない。

## 事前検査の記録

- Claude Code 2.1.323: ローカルstubでBash/Read/Writeを強制要求し、全てNo such tool available。canary不変、新規書込みなし、4要求・CLI終了0。
- Codex 0.169.0: 実binary hash `739cda86e15d30a6e2b40cf8dcbbfb988aaf48b305b27065573bb8e9fd41d002`。exec_command/apply_patch/view_imageを強制要求し全てunsupported call。canary不変、新規書込みなし、4要求・CLI終了0。
- Codexのfail-closed化後の再検査は `/private/tmp/tempest-m6-codex-preflight-004/summary.json`。
  4要求すべてでtool catalogは `request_user_input` のみ、同一hash、3拒否・canary不変・書込みなし。
  API要求0またはhost書込み後に終了0を返す偽CLIはprobe自身が非0になる2負例を追加した。
- Claudeの同じ再検査は `/private/tmp/tempest-m6-claude-preflight-002/summary.json`。
  4要求すべてでtool catalogは空かつ同一hash、3拒否・canary不変・書込みなし。
- 証拠は `/private/tmp/tempest-m6-claude-preflight-001/summary.json` と `/private/tmp/tempest-m6-codex-preflight-003/summary.json`。
- この2試行はMCP未接続で、HMAC/hostfwd迂回・許可MCPの正対照は未検証。実launcherの受入完了ではない。
  `observed` はこのローカルstub観測の成立だけを表し、launcher受入を意味しない。許可MCPの正対照と
  本番各requestのtool集合一致・能力追加拒否は未実装である。
- Codexの先行2試行は、shim解決失敗と別版0.142.2の未知feature拒否でモデル要求に未到達。成功試行に混ぜない。

## 議論から追加した条件

Sakura15356: runごとに空のHOME/設定領域を与え、普段のinstructions・memory・他MCP・hookを
読み込まない。認証は明示した必要情報だけを渡す。modelの正確なID、CLI hash、生成設定、予算を
固定する。host CLIのモデルAPI通信とguestのnetwork制限は別境界で、host側の許可先・拒否/記録の
実効性を検査する。能力としてweb取得を強制する負例も追加する。
modelの拒否は独立軸とし、単なる最終文のキーワードだけで自動確定しない。
API障害・rate limit等で必要観測が成立しないrunはunknownとして残す。

## 対照中に発見した配送障害

`/private/tmp/tempest-m6-noop-001/noop-1` は成功（tool/API 0、計上0・未確定10）。
`noop-2` はseal後exportで管理exec不確定となりaborted/partial、全cleanupは成功した。
3回成功した対照とは扱わない。既存#13へ証跡とfreeze/応答取得の競合仮説を追記した。
具体的な失敗応答の形式は未保存なので未確定。hostに秘密本文を転記せず応答種別だけを残す
診断を加え、異なるrun IDで再検証する。root operationの再投入は行わない。

## no-op反復対照の結果

`/private/tmp/tempest-m6-noop-002/` は3回全てcompleted/performed。各回の
MCP call/API要求は0、findingはnot_found、計上候補0・未確定10で一致した。
未確定内訳はdoas3・tempest-guest wrapper3・native2・api.jsonl/capture.pcap各1。
各評価世代の成果物hashを検査した。`noop-summary.json`に評価IDと内訳を保存した。
この3成功と、先行実験の1成功・1失敗を区別して保持する。成功率や正式モデル比較とは呼ばない。
通常mockの未確定11との差はbackend/bypass候補1件だが、差分を主体帰属や控除の根拠にしない。
管理配送の競合は修正していないため、3成功から障害解消とは結論しない。

強制再現fixture（PR32 d7f570f）を別imageとしてbuild中。
root readerの待機PIDとquiesceのmoved_pids、同一要求IDへの失敗/成功読取を照合する。
通常prepareの生成dispatcher/quiesceは元のscript bytesと一致し、metadata hashも一致した。
Python既存19試験成功。実VMの強制再現結果はまだ得られていない。

最初のfixture VM試験は、marker更新に一度きり作成用helperを流用したため、
wrong-daemon負例の反復読取で停止した（`/private/tmp/tempest-m6-delivery-race-vm-001/`）。
これはfixtureの不備であり、配送競合の原因確認には数えない。markerを私有一時ファイルから
atomic replaceする方式に修正し、同一markerの反復更新を確認した。
修正版は `/private/tmp/tempest-m6-delivery-race-build-002/` で別buildとして保持する。

Sakura15364の指摘を受け、freeze中はRPC daemonも止まり、大証跡ほど読取が無応答になる偏りを
再試行設計へ含める。root native exportの240秒、quiesce/thaw各20秒、固定MCPの外側300秒を
別々に扱い、host全体期限との整合と上限近くの証跡による実測を行う。
この経路の失敗runもunknownとして分母内に残す。
完了exportのbarrierへmonotonicによるfrozen_duration_nsとthawed_guest_nsを追加した。
mailbox9試験は成功したが、現在build002にはこの時刻追加は未搭載で、実VM計測は未確認である。

build002はhost容量不足によるQEMU `paused (io-error)` / `I/O status: nospace`を
monitor画面で確認した。容量確保後の再開2回でも同状態へ戻ったため正常中断した。
観測timeoutだけを理由に再起動したものではない。入力・生成scriptは保持し、
容量確保後のbuild003へ進めた。build003はfreeze時刻記録を含む。

hostのcontrol.jsonlには各delivery読取の開始と観測分類を同じ管理要求IDで追記する。
暗号文受信は認証済みoperation成功とは呼ばず、RPC不確定・reply未生成・実行失敗と分ける。
監査I/Oが失敗した場合も成功扱いにせずVMを破棄する。再試行条件は未変更である。

## 配送競合の実測と修正

- build003のimage_smoke成功: `/private/tmp/tempest-m6-delivery-race-vm-003/summary.json`。
  実root reader PID1304がmoved_pidsに含まれ、実行失敗→同IDの認証済み応答取得を確認。
  freezeは107209167ns。fixture以外の隔離試験も同じsuiteで実施した。
- 修正前host（3c7a777）の実管理MCP: `/private/tmp/tempest-m6-delivery-race-baseline-003/`。
  export投入1回、exit_minus_one読取失敗1回でaborted、partial評価・安全回収。
- 修正後host: `/private/tmp/tempest-m6-delivery-race-fixed-003/`。
  primary export投入1回・失敗1回から回復しcompleted。reader PID890、freeze137149417ns。
  その後fresh retestのprobeも成功。retestはexportを行わず、retest側の強制競合を実測したという意味ではない。
- process peer試験は、export失敗3回の打切り、seed失敗・RPC ID不一致・companion認証失敗・operation拒否・未知応答の即中断を確認。
- 上限に近いPCAPは `/private/tmp/tempest-m6-delivery-race-large-003/` で実測した。
  60,954,815 bytesのPCAPと29 API行を同一export IDで回収し、各ファイルのbyte数・SHA-256が
  receiptと一致した。root reader PID862はmoved_pidsに含まれ、exit_minus_one 1回後に再投入せず
  認証済み応答を取得し、freezeは118,546,208ns、VM cleanupも完了した。ただしtcpdumpがkernel
  drop 10件を報告したためmanifestはincomplete、runはaborted/partialであり、正式完了とは扱わない。
  `runtime_delivery_race.py --expect collected --large-evidence` は、この「全配送物を回収したがrecorder
  証拠は不完全」という状態をcompletedから分離して検証する。
  このhost側64MiB制限はexport応答後に検査され、guestの複写・fsync・hash量を制限しない。
  したがって本試験は敵対的証跡量に対するfreeze上限の証明ではない。上限直上、guest disk枯渇、
  native timeout後のcleanupは未検証で、発生runはunknownとして分母に残す。

修正した通常hostの条件は [M4実行契約](M4-CONTRACT.md) を参照。

強制再現imageは `delivery_race_fixture=true` をrunのimage metadataへ残す。評価器はこの値を
`formal_metrics_exclusions.test_image_fixture` に写し、trueなら他の条件にかかわらず
`formal_metrics_eligible=false` とする。これは試験fixtureの混入防止だけであり、#17で検討中の
検証用実行と正式評価を分ける一般ゲートの採否を決めるものではない。

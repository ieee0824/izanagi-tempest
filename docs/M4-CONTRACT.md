# M4 実行契約（実装中）

対象は #5、関連契約は #13/#14/#15。M0〜M3の完了範囲を変更しない。
room投稿15132〜15137の議論を反映する。`tempest plan`と主体bindingは実装、
VM orchestration/MCP proxy/回収barrier/結果集計は実装中であり、計画成功を実行成功としない。

## 主体の解決

YAMLへ新しい主体フィールドは追加しない。`tempest validate`の静的入力契約を維持する。
`tempest plan SCENARIO [--actor NAME]`はVMを起動せず実行主体と段階の有無を解決する。
単一setup userは一意に選択し、複数なら`--actor`が必要。先頭、taskの文面、retest.userから推定しない。
未解決・未知のactorは`runtime.actor`の診断であり、静的入力の不正とは区別する。

primaryのself-check、agentへ渡す唯一のworker資格情報、expect、finding照合は同一actorを使う。
seed応答は全setup userについて重複のないキーが揃うことを検査する。
bindingはrun ID、primary/retest段階、actor、typed policy JSON SHA-256、AccessKeyId SHA-256を束ねる。
元キーは監査JSON/Debugへ出さず、probeとagent promptへだけ渡す。
これは固定LWS seed応答からの対応付けであり、SigV4認証成功の証明ではない。

promptはtask、選択した1組の資格情報、公開endpoint/region/path-styleと報告指示だけを含む。
bindingのrun/stage/actor/policy revisionがprimary計画と違えば生成しない。
setup、expect、finding、他userのキーを混ぜない。

retestではprimary setupを変更せずcloneし、既存のretest.userのpolicyだけを置換する。
他のusersとバケット/オブジェクト/キューを含むsetup全体を新VMへseedし、そのuserの新しいキーでprobeする。
元シナリオ・primaryのseed結果と、retest側のsetup/seed結果を私有run証跡で別々に保持する。
再seedのキーは新しいため段階間のキー一致を要求しない。段階ごとのregistryで照合し、旧キーを流用しない。

plan/binding factoryはstatelessであり、同run・同primary policyの再seed後の現在性を単独では保証しない。
既存の旧キー負例はprimary/retestの段階間についての試験である。
M4 controllerは同一run/段階のseedを1回だけにし、seed応答喪失/失敗後はVMとrunを破棄する。
再試行には新run IDを発行する。retestは同runの別段階として1回だけ新VMを作る。
controllerのone-shot所有状態と正負試験を実装してからこの不変条件を確認済みにする。


retestがprimaryと別actorなら独立したpolicy検証として扱う。
同一actorかつfindingと同じAPI/resourceへのdeny checkがある場合のみ、修正確認の対象になり得る。
`repair_intent=targeted_repair_check`は必要条件の計画であり、成功判定ではない。
finding無し、別actor、対応deny check無しのretestをprimary findingの修正成功へ混ぜない。
同じpolicyを指定した入力を静的に一律拒否することもしない。

## finding / retest の4通り

いずれもtaskを実行するagent段階とexpect基準線の観測を持つ。省略した親を生成しない。

| finding | retest | self-check | agent | finding評価 | 新VM retest |
|---|---|---|---|---|---|
| 有 | 有 | primary actorでevidenceがallowか確認 | seal成功後 | 証跡と報告を照合 | retest.userで指定check |
| 有 | 無 | 同上 | 同上 | 同上 | not_performed/not_configured |
| 無 | 有 | not_performed/not_configured | 同上 | not_performed/not_configured | 指定check（独立policy検証） |
| 無 | 無 | not_performed/not_configured | 同上 | not_performed/not_configured | not_performed/not_configured |

自己検証が不成立/unsupported/errorなら測定対象agentを開始しない。
予算0は静的には有効であり、実行ではadmission前の即時打切りとして扱い、成功を生成しない。
低レベルIzanagi execはmapping検査・制御応答取得に必要なのでseal前でも使用する。
seal後に限るのは測定対象agentの開始である。

結果では`configured`（親の有無）、`performed`（実施有無）、結果、未実施理由を分ける。
not_configured、upstream_aborted、runtime_error等を未発見/失敗/成功へ黙って合算しない。
runのbudget/timeout/abort/contaminationと証跡完全性も別軸で保持する。
集計は指標ごとに設定対象数・実施数・証拠適格数・中止/汚染/欠損/未設定数を明記する。
具体的なresult型と集計の試験は#6/#7で実装し、#14はその接続まで完了扱いにしない。

## 配送と終了境界（実装・実VM検証待ち）

sandboxはM3のroot-private mailboxだけを例外とする。agent-cwdは空に保つ。
Mailboxのroot mappingはVM起動前に確定し、入力の一時ファイルも私有inbox内に置く。
root consumerが要求を自律処理し、doasは保存済み暗号文を非破壊取得するだけである。
サイズ/nonce/障害時処理は[image/README.md](../image/README.md)に従う。
実Linux host全体は未実施。その環境を採用する際のmapping検査をfail-closed条件として残す。

終了barrierの案:

1. proxyのagent admissionを閉じ、新しいtools/callを中継しない。
2. forward済み全RPC応答を有限期限で収束させる。固定agentのExecは最大300秒で結果を返す。
   下流接続喪失・期限切れで実行中要求を収束したと証明できなければ、通常exportへ進まずVMを破棄する。
3. root consumerが固定`izanagi-agent.service`のcgroupを検証してfreezeする。
   MainPIDはrootのIzanagi RPC daemonであり、測定対象AIのhost CLIではない。
   agentが所属を書き換えられず、consumer/control/LWS/captureが別cgroupであることを確認する。
4. root MainPIDを除く所属processをUIDによらず終了する。doas子、setsid/reparentした子も含む。
   freeze下で測定対象を別sub-cgroupへ移し、kernelのcgroup.killで再帰的に終了させる案を検証する。
   対象subtreeのpopulated=0と、親に検証済みroot daemonだけが残ることを確認する。
   管理MainPIDを残した親cgroupを「空」とは呼ばない。必要なthaw後も有限期限で確認し、
   失敗ならexportしない。これはSIGSTOPだけで回収済みとする案ではない。
5. root daemonを再開し、以降のexecはhost管理操作だけにする。agent側proxyは閉鎖済み。
   guestの非rootからTCP9001への直接制御経路を追加owner制限で閉じる案を検証する。
   Hostfwdの制御を壊さないこと、fw_cfg token/secretの読取り拒否、未起動依頼の残留を確認する。
   停止前後の所属/PID/starttime/結果を私有証跡に保存し、確定不能なら通常exportを拒否する。
6. agentとゲスト内対象の終了確認後にexportを最終化し、証跡回収→VM downを行う。

単なるホストCLI終了やUID/PIDの一度きりの列挙だけでは回収済みとしない。
cgroupの所有/委譲、freeze/終了/再走査、inflight応答との順序、正常/予算/timeout/異常/回収失敗は
固定VMで検証してから採用する。現時点では実装・検証未了。

## 現在の検証

planの8試験は4presence、複数userの明示解決、retestの限定置換、資格情報・policy revision、
旧キー拒否、seed registryの不足/衝突、promptへの私有値非混入、CLIのruntime未実行表示を確認する。
これだけで#5/#14/#15全体の実行・評価・集計が完成したとはしない。


## MCP admission基礎（relay接続前）

`admission` moduleはtool callの許可・期限・pending応答を追跡する。
上限超過/期限切れは新しいpermitを発行せず、重複request IDでpendingを上書きしない。
受付を閉じてもpendingを消さず、観測した応答でだけcompleteにする。
接続喪失/収束期限切れは不可逆にuncertainとし、後着応答があってもverified receiptを生成しない。
`DrainReceipt`はRPC収束だけの証拠であり、ゲストprocess終了の証明ではない。
4試験で上限/0/期限/重複/未観測応答/接続喪失/期限後応答を確認する。
実MCP relayの中継・ログは下記のstdio実装で接続した。Host/VM shutdownへの接続は未実装。


### 固定MCPの外側timeoutに関する反例

固定Izanagiの`src/commands/mcp/mod.rs`はJSON行ごとに応答を待つ逐次server。
`src/commands/mcp/exec_capture.rs`も300秒で`exec_on_session_raw`をtimeoutする一方、
guestの`izanagi-agent/src/exec.rs`の300秒はguest側でspawnした後から始まる。
したがってMCP側timeout/exec transport errorの応答だけで、guest callbackの終了は証明できない。
RPC収束receiptとguest終了確認を同一視しない。

relayではtool呼出しを上流へ無制限に先送りせず、未転送queueと実inflightを区別する。
上流のexec失敗・不明な応答/接続喪失等でguest完了を確認できなければ、受付閉鎖済みでも
通常exportへ進めずVM破棄と証跡欠損理由を記録する。
コマンドの非0終了（例:期待した認可拒否）をtransport失敗と混同しない判別は、
固定serverの結果形式と実際のRPC/VM故障注入で検証してから使用する。


## stdio MCP relay（VM controller接続前）

`tempest mcp-proxy`は固定Izanagiの逐次JSON-lines serverを対象とする。
1つだけを実inflightとし、未転送queueは32frames/合計8MiBに制限する。
agent入力は4MiB/行、上流応答はescaped stdout/stderrを考慮して8MiB/行。
initialize/tools/listの内容・tool説明・schemaを変更せず中継し、tools/callの転送permitだけを予算に数える。
重複ID/queue上限/不正frameは転送しない。断片frameはtimer/control待ちのキャンセルで失わない。

queued→dispatch_ready→forwarded/forward_uncertain→responseをmcp.jsonlに記録する。
dispatch_readyは転送候補であり、転送済みの証明ではない。監査I/Oの後でもう一度
受付/期限を検査してからpermitを出す。途中切断時にforward済みのpendingを消さない。
agent入力のhalf-close時は既に受信したqueueを処理できるが、controllerから明示closeされたら
未転送要求は拒否する。Host runtimeは測定対象終了時に明示closeを送る。

上流切断・ID不一致・不正応答・drain期限切れ・exec failed等の完了不明な応答では
不可逆uncertainとし、verified drain receiptを出さない。
固定tools.rsの通常非0exitは末尾のexit-code形式と区別する。guest出力がexec failedを模倣する等の
曖昧さは保守的にuncertainのままにする。この判別は固定形式fixtureで検査したもので、
実VMでの非0終了/外側timeout故障注入とcontrollerのexport禁止への接続はまだ行っていない。

CLIのlog/summary/stderrは同一user所有0700の親に新規0600で作る。
既存fileを上書きせず、上流へHOME/PATH/TZとTERM=dumb以外の環境を引き継がない。
summaryのscopeはrpc_transport_onlyで、CLI終了0も実験成功やguest子孫終了を意味しない。
agent側書込み先が閉じても上流応答をdrainし、結果不明なら通常exportを禁止する扱いをcallerへ返す。

12件のstream試験と2件の実process CLI試験で、metadata透過、quota/0/close、queue上限、
切断後drain、外側exec失敗、通常非0/模倣出力、frame断片/上限、ID不一致、監査遅延中の期限切れを確認。
固定Izanagi CLIの実processでもinitialize/tool定義が直接実行と一致し、予算0の要求を拒否した（VMなし）。
比較証跡はGit外の`.m0-evidence/20261112-mcp-relay-current/`。
再現時はビルド後、固定Izanagi実行ファイルと新規出力先を指定する。

```bash
python3 integration/mcp_metadata.py --tempest target/debug/tempest --izanagi /absolute/path/to/izanagi --output /private/tmp/tempest-mcp-metadata-001
```

`comparison.json`に両実行ファイルのSHA-256と確認範囲を記録する。VMは起動しない。

測定対象agentをkillするgroupの中に、drainを担うsupervisorまで置いてはならない。
Run controller所有の独立supervisor、agent側stdio bridge、VM cgroup回収、
clock/run記録、mock E2Eは次の実装であり、#5/#13/#14/#15はまだ完了ではない。

## one-shot seed状態の所有

`SeedController`は私有0700のruns root内でrun IDのdirectoryを排他的に作る。
失敗・drop後も予約を削除せず、同じIDからの再構築・resumeは受け付けない。
段階ごとのseed試行を0600の新規markerへ書き、fileとdirectoryのfsyncが成功してから
transport closureを1回だけ呼ぶ。markerは試行開始の証拠であり、配送・seed成功の証拠ではない。

応答を待つ間は資格情報を使用できない。応答喪失・不正registryでは全bindingを無効化し、
失敗理由にtransportの生の診断や秘密を転記しない。futureがキャンセルされた場合もAwaitingが残り、
prompt/probe/claim照合を拒否し、次のseed要求はtransportへ到達しない。
runtimeはこの状態でVMを破棄する必要があり、タイムアウト後の同run再seedはしない。

prompt/probeとclaim照合はcontrollerが保持するbindingだけを使う。
primary/retestのregistryは別々に結び、audit metadataには生キーを出さない。
全userのキー指紋を段階間で比較し、過去段階のキーを再利用したregistryも拒否する。
6試験で再送禁止、intent先行記録、応答喪失、不正registry、キャンセル、run ID再利用拒否、
段階ごとのpolicy/key照合・旧キー再利用拒否を確認した。これはVMのfreshnessや破棄を実測した証拠ではない。
retest transportの新VMへの接続、実mailbox呼出し、VM破棄は後続controllerで接続する。

# Linux x86配送競合M3 smoke001

## 結果と対象

room16816の最終監査後、[固定snapshot](LINUX_X86_DELIVERY_RACE_SMOKE_SNAPSHOT_001.json)からM3 forced-reader smokeを一度だけ実行した。
caller20069は終了コード0、独立collector74064も終了コード0。[安全な結果投影](LINUX_X86_DELIVERY_RACE_SMOKE_001_RESULT.json)と[collector source](evidence/delivery-race-smoke-001/collect_result.py)を保存した。
host Tempest CLIのcompleted試験・大容量control・実モデル比較は今回実行していない。

直前検査79957は終了コード0、free12605267968 bytes。入力1314項目・23固定source・外部runtime・旧証拠不変、UID999空、unit未使用、出力不在、KVMを確認した。
固定snapshot内observer70362を先行し、専用root/unitの監査済みcallerを単発起動した。再試行・既存rootの再利用は行っていない。
Invocationは`332f962b2818418fba1f221e843f3777`、bootは`30389abc903c40ae89a5c6268ec1c432`。

## 競合と回復

実root reader PID1496を強制待機させ、quiesceのmoved_pids `[1490,1493,1494,1496]`へ含まれることを確認した。
primary export ID `9c55d3bf577cbad6d4a6c80e6ea5a6be`の読取は`execution_error`から`reply`へ回復した。
固定smokeは実行中に応答を認証・復号し、要求の再投入なし（operation_submissions=1）でcomplete export、service_frozen、descendants_emptyを検査した。
collectorは保存された全export read metadataを実private streamの終了コード・stdout/stderr digestと照合し、認証復号を再実行していない。
exec operationのexport4件は誤daemon identityの拒否対照とprimaryの配送readであり、primary要求を4回投入したという意味ではない。

必須M3のclaim/seed/probe、200/403/501、owner/doas・private request/response・read-only mapping・RPC/backend拒否、通常/timeout/異常子孫終了、recording boundary、実eBPF trace、artifact bindingとhost log scanを実行した。
guest manifestはfixture=trueで固定prepareの全fieldへ一致し、親binaryのcompile provenanceも保持されている。
このfixture固有の競合回復成功を一般の配送期限・全障害条件の証明にはしない。

## Private execと独立終了確認

175実行・350stream・525file、host timeout0、expected_error_reads6。
保存中のprivate marker scanはpassed/leaked_streams=[]。collectorは連番・operation件数・終了/timeout属性・file集合/sizeとUID999:GID988、directory0700/files0600/single-linkを照合した。
private markerや復号鍵の回復・marker再scanは行っていない。host CLIで採取したstreamの範囲であり、短命native PIPE・全期間のproc/FD内容へ一般化しない。

observerは68sampleでQEMU PID314914/starttime38232597と固定workspace cwdを観測し、runtimeの既存隔離条件を検査した。外部listener観測とpolicy検査エラーは0。
unit GC後の同Invocation終端属性を取得できずobserverは終了コード1となったため、終端判定はunknownのまま保持する。
独立ExecStopPostのexited0/successとPID1/root/current boot/同unit/同InvocationのStarting・Started・Deactivated journalで正常終了を確認した。
専用UID999プロセス・cgroupは不在、観測したloopback port46235は閉じている。入力1314項目・外部runtime・旧証拠は不変。

dummy transport keyは結果監査を待ってprivateのまま保持し、collectorは値・hashを読み出していない。cleanupは別記する。
次はこの結果の監査後に、別rootの固定host CLI mock completed試験へ進む。[後続runtime計画](LINUX_X86_DELIVERY_RACE_RUNTIME_PLAN.md)を参照。

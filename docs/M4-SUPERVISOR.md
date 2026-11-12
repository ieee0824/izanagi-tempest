# M4 独立MCP supervisor

## 実装範囲

`Supervisor`が上流Izanagiと監査fileを所有し、agent側は`mcp-connect`でUnix socketへ接続する。
上流は独立process groupで起動する。agent/bridgeのgroup終了で上流をkillせず、転送済み応答を回収する。
同一socketへ接続できるbridgeは1つだけ。親directoryは同一user所有0700、socketは0600。

この境界ではbridge入力EOFをagent終了として明示closeへ接続する。
汎用relayのhalf-closeとは異なり、EOF観測後の未転送queueは配送しない。
close通知で最初に受理した理由だけを保持する。敗者の通知は現在保存しないため、
物理的なagent終了とowner closeの順序をこのreceiptだけから再構成しない。
詳細なlifecycle時刻・全終了通知は後続のrun監査に接続する。
agent起動待ちも同じtimeoutに含み、接続時に予算を更新しない。
`finish(reason)`はcloseとdrain待ち、`wait()`はEOF/期限等による終了待ちである。
ownerのdropもcloseするが、receiptを受け取っていないcallerは通常exportへ進めない。

`mcp-session`は外部controller/結合検査用の常駐owner CLIである。
stdinを持つのはbridgeなので、ownerはagentのstdio寿命に依存しない。
上流が終了したら、peerがstdinを保持していてもbridgeを終了する。
従来`mcp-proxy`にも、予算終了時にTokio stdinのblocking readを待ち続けない修正を入れた。

## transport HMAC

VM起動と同じdummy HMACを明示`--secret-file FILE`で指定する。
ambient `IZANAGI_SHARED_SECRET`やAWS credential等を上流へ引き継がない。
fileを`O_NOFOLLOW|O_NONBLOCK`で開き、同FDのfstatで通常file・自UID・0600・非空・4096 bytes以下を確認する。
親directoryは自UID所有かつgroup/other書込不可とする。FIFOはblockせず拒否する。

検査済みFileを保持し、上流のfork内だけでそのFDのCLOEXECを解除する。
上流へ渡すのは`IZANAGI_SECRET_FILE=/dev/fd/N`であり、元パスを再openしない。
親のFDはCLOEXECを維持し、別agent子のexecへ継承しない。
秘密値をargv/env/監査に置かず、元パスや長さをruntime診断へ転記しない。
operator自身の`--secret-file`引数には指定パスがあるため、これはパス名の秘匿を保証する機能ではない。

Darwinの`/dev/fd`は読み位置を共有する。固定MCPは要求ごとにHMACを読むため、
ownerが保持するprivate dupを各frameの最初のwrite前にseek(0)する。
前要求の応答を観測するまで次のframeを送らない逐次relayと、固定上流の1読取/要求に依存する。
変更した上流・並行reader構成は再検証が必要であり、未知のreaderを一般検知する機構ではない。
親directoryと実行ファイルはcontrollerが管理する信頼境界である。

## 起動例

既に起動しているIzanagi sessionと同じcwdを指定する。ownerはagentと別に起動する。

```bash
mkdir -m 700 /private/tmp/tempest-session-001
target/debug/tempest mcp-session /private/tmp/tempest-session-001/s \
  --log /private/tmp/tempest-session-001/mcp.jsonl \
  --summary /private/tmp/tempest-session-001/summary.json \
  --stderr /private/tmp/tempest-session-001/upstream.stderr \
  --cwd /absolute/path/to/sandbox \
  --secret-file /absolute/path/to/private-dummy-hmac \
  --max-calls 50 --timeout-ms 900000 \
  -- /absolute/path/to/izanagi mcp
```

agentへ登録するstdio server commandは次である。agent launcherは秘密設定を含まない環境を用意する。

```bash
target/debug/tempest mcp-connect /private/tmp/tempest-session-001/s
```

summaryのscopeは`rpc_transport_only`。owner終了0/verified receiptはguest子孫終了や実験成功を意味しない。
不明な結果・receiptなし・上流異常終了では通常exportせずVMを破棄する。

## 検証

Rust全65件、Python18件、fmt/clippy/diff check成功。
supervisorの10試験はgroup kill後drain・queue未転送、接続なしclose/期限、stdin保持時server EOF、
socket親権限、HMACの明示FD・ambient非継承・symlink/0644/書込可能親/FIFO拒否、
検査後のpath差替え、別agent子fixtureへのFD非継承、要求ごとの繰返し読取、競合readerの失敗を扱う。
競合readerの負例では固定形式のexec failedを観測し、uncertain/receiptなしになることを検査する。
任意の競合が必ず検知されるという証明にはしない。

実VMでは[終了確認と同じimage](M4-QUIESCE.md)に対し、次を実行する。
`image_smoke.py`はtempest binaryをrun専用fileへcopyして固定し、専用dummy HMACを生成する。

```bash
cargo build --locked -p tempest
python3 integration/image_smoke.py --izanagi /absolute/path/to/izanagi --image /absolute/path/to/debian-aarch64.qcow2 --build-inputs /absolute/path/to/inputs.json --tempest target/debug/tempest --output /private/tmp/tempest-supervisor-001
```

`agent-evidence/`にmcp.jsonlとowner summary、`guest-evidence/`にAPI/PCAP/manifestを保存する。
2 GETをMCPで実行し、3件目のtouchを予算拒否する。sent=completed=2/pending0のreceiptを確認してから
guestのcgroup exportへ進む。予算拒否されたfileがguestに存在しないことも確認する。

### 実VMの記録

image SHA-256は`1d8e564d72c68a39ab7e78551e73e0d6e61190fa9101596e01c53e0e00eb9e7c`。
Izanagi/LWS本体、snapshot/read-only/network制限は[M4終了確認](M4-QUIESCE.md)と同一。
host binaryは`c0e3030`へ本差分を加えたtreeからビルドした。

| run | 条件・結果 |
|---|---|
| 001 | HMAC参照を除去した初期実装。metadata成功、最初のexec失敗。uncertain/receiptなし、exportなし |
| 002 | 明示path版。2 GET・予算拒否・drain・export成功。最終FD方式の証拠には使わない |
| 003 | FD版、rewindなし。Darwin共有offsetにより2件目失敗。uncertain/receiptなし、exportなし |
| 004 | FD+rewind版。2 GET、3件目未転送、2/2 drain、cgroup export成功。39 packets/drop0 |
| 005 | 最終CLI/close first-winsを含む版。同じ検査が成功。40 packets/drop0 |

run005 host binary SHA-256: `e713b02f4fbad124b0b2794202111e608192b581cbff621a7f545eec87379983`。
run005 summary SHA-256: `894c5c14bacd19a49b17e511627ddefd487e488fdae081294b6875cbca8f935e`。
run004 summary SHA-256: `2c99225c233cc26a8cb21c3bf377693ab3427bbd594b656ff199d679f4449552`。
Git外の私有証跡 `.m0-evidence/20261112-m4-supervisor/` に保存し、snapshot binaryのhashと
export fileの長さ/hashを再照合した。run001は初期診断であり、binary snapshot固定前の記録である。
失敗runでexportしなかったのはこの結合検査の中止経路であり、正式run controllerの完成を意味しない。

## 未完了

これは決めた2 GETを送る結合検査であり、`s3-overread-001`の正式mock adapter E2Eではない。
`tempest run`、AgentAdapter/mock、one-shot seedと実VM破棄の結合、retest新VM、clock/run記録は残る。
測定用supervisorはMCPを使うが、既存image smokeの管理処理にはCLI execが残っている。
固定CLI execはsession喪失時に単発起動する経路があるため、正式controllerでは自動起動しない
固定MCPの管理経路へ置き換え、upの寿命・daemon identityを検査してから採用する。
実model CLIの隔離・環境検査は#7、結果と集計は#6/#14、配送の全体表は#13で継続する。

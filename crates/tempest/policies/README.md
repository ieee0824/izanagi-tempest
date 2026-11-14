# Native CLI model request policies

ここに置く JSON は、native CLI の discovery 結果から実行時に自動生成する許可一覧ではない。CLI version と provider protocol ごとにレビューし、正式な acceptance で完全一致を要求する契約である。

`claude-code-2.1.323-<MODEL>-anthropic-messages.json` は Claude Code `2.1.323 (Claude Code)` の `anthropic-messages` 契約をexact model IDごとに固定する。現在のreview対象は `claude-sonnet-5-5` と `claude-haiku-5-5` であり、aliasやdiscovery専用の架空modelは許可しない。同じrequest形でもmodelごとにpolicy fileを分け、別々のreview単位とする。CLI が送る認証 header、`anthropic-beta`、telemetry/SDK header は上流へ転送しない。model API relay は JSON に記載した `request_headers` のみを再構成し、実認証をrelay側で追加する。

model IDとretirement予定は2026-11-14にClaude Platform公式の[Models overview](https://platform.claude.com/docs/en/models/overview)で確認した。4.6以降のdateless IDがaliasではなく固定snapshotである根拠は[Model IDs and versioning](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions)による。modelを変更する場合は、新しいpolicy fileのreview、native discovery、proof、LaunchPermitをすべて再実施する。

field、path/query、value type、tool schema、固定 header のいずれかが変わった場合はfail-closeとし、ファイル更新は差分をレビューしてから行う。

### Messages requestのレビュー記録

2026-11-14時点のClaude Platform公式[Messages API](https://platform.claude.com/docs/en/api/messages/create)、[Thinking](https://platform.claude.com/docs/en/build-with-claude/thinking)、[Effort](https://platform.claude.com/docs/en/build-with-claude/effort)、[Context editing](https://platform.claude.com/docs/en/build-with-claude/context-editing)、[Prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)と照合した。許可は次の用途に限定する。

| field / type | 公式上の用途 | Tempestでの判断 |
| --- | --- | --- |
| `model` | 応答modelの指定 | exact IDをpolicy別に1件だけ固定する。 |
| `max_tokens` | thinkingを含む生成tokenの絶対上限 | CLIが選ぶ有限値を許可するが、relayのrequest件数上限とは別である。 |
| `messages` / `system` | 会話履歴とsystem prompt | Tempest生成prompt、固定CLIのtool loop、MCP resultだけを運ぶ。host fileを追加取得する経路ではない。 |
| `tools` | client toolのschema | live Izanagi catalogと完全一致する3 toolだけを許可し、requestごとに再照合する。server tool typeは許可しない。 |
| `stream` | Messages応答のSSE streaming | relayのbounded streaming経路で扱い、全bufferしない。 |
| `thinking: {type: adaptive}` | modelがrequestごとにthinking量を決める | 出力token・費用へ影響するが、新しいhost/外部tool権限は増やさない。 |
| `output_config` | response全体のeffort・format設定 | field自体を許可する。`type` discriminatorは集合で制限するため`json_schema` formatは拒否するが、effort値そのものは固定しない。tool call回数・費用に影響し得るため、model request budgetを独立に強制し、比較時は観測されたrequest policyとCLI/model条件を記録する。 |
| `context_management` / `clear_thinking_20251015` | 過去turnのthinking blockをcontextから除くbeta context editing | request内の会話contextを縮めるだけでhost accessは増やさない。正式APIで必要なbeta headerは未確認であり、低額preflightまでは本番互換性を主張しない。 |
| `metadata` | opaque `user_id`をabuse検知へ渡す | host capabilityではないがproviderへ値を送る欄である。relayは値を固定していないため、Tempestの秘密・資格情報をpromptへ含めず、固定CLIが生成したopaque ID以外を承認したとは扱わない。将来CLIがmetadataの用途・形を変えた場合はpolicy schemaを拡張してfail-closeする。 |
| `cache_control: {type: ephemeral}` | tools→system→messagesの同一prefixを5分（`ttl: 1h`指定時は1時間）cacheし、費用・latencyを下げる | relayは`type: ephemeral`を検査するが`ttl` key/valueは固定しないため、1時間cacheも通り得る。cacheはworkspace単位で隔離されexact prefix一致を要求するがprovider側に最大1時間の状態を作るため、run間独立性の根拠には使わず、比較条件では同じ固定CLI/model/policyを要求する。 |
| `text` / `tool_use` / `tool_result` | 通常textとclient tool loopのcontent block | tool名/schemaは別途完全一致し、resultはMCP bridge由来に限定する。image/document/server-tool blockは型集合にないため拒否する。 |

`request_value_types` はJSON中の全 `type` discriminatorの許可集合であり、任意の同名featureを許可するものではない。top-level field、tool schema、path/query、model、catalogの完全一致と組み合わせる。上記公式資料でbeta header不要と確認できるのはadaptive thinking/tool use/streaming等であり、`context_management`の正式Anthropic API互換性は未確認である。relayはCLI由来の`anthropic-beta`を転送しないため、実API低額preflightで必要headerを確認し、差分があれば本policyを再レビューする。

`acceptance_requests` はdeterministic probeで観測・再現する件数で、現在は8である。`maximum_requests` はproduction relayが上流へ送信できる独立した有限budgetで、現在は19とする。CLIの`--max-turns 20`より1件少なくし、20件目をrelayが拒否する実CLI負例を作れる保守的な費用上限であり、retry余裕は含めない。SDK retryや補助requestも1件として消費し、上限到達で中止したrunは成功・失敗に変換せずUnknownとして事前計画の分母に残す。両値はpolicy hashを通じてprofile/proofへ固定し、runtime varianceとして変更しない。

`claude-code-2.1.323-macos-system-paths.json` は、このCLI版がmacOSで参照し得るorganization-wide `CLAUDE.md`、managed settings/MCP、machine/user MDMのsystem側パスと、Tempestが依存するSeatbeltファイルを列挙する。`{USER}` はrunnerの実効uidから解決し、managed pathは起動時に不在、Seatbeltファイルは実行時hashをprofileへ束縛する。この一覧は公式に文書化された既知の高優先度設定・指示源が混入していないことを保証するが、CLIの全file accessを独立にtraceして網羅性を証明したものではない。

managed settingsの場所と優先順位はClaude Code公式の[Managed settings](https://code.claude.com/docs/en/managed-settings)、organization-wide指示は[Memory](https://code.claude.com/docs/en/memory)を根拠とする。Tempestはnon-Anthropic `ANTHROPIC_BASE_URL` を固定するため、同文書の仕様上server-managed settingsは取得されない。user/project/local settingsは空のprivate HOME/CWDと`--setting-sources ""`で除外する。

macOS `system.sb` は `cfprefsd` とのMach通信を許可するため、MDMをfile denyだけでは制約しない。TempestのSeatbelt profileは`com.anthropic.claudecode` domainへの`user-preference-read`を明示拒否し、machine/user MDM plistの不在検査と組み合わせる。通常file accessは専用jailだけを許可する。これらは別々の境界であり、一覧外の設定源が存在しないことをfile deny単独では主張しない。

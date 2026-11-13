# Native CLI model request policies

ここに置く JSON は、native CLI の discovery 結果から実行時に自動生成する許可一覧ではない。CLI version と provider protocol ごとにレビューし、正式な acceptance で完全一致を要求する契約である。

`claude-code-2.1.323-<MODEL>-anthropic-messages.json` は Claude Code `2.1.323 (Claude Code)` の `anthropic-messages` 契約をexact model IDごとに固定する。現在のreview対象は `claude-sonnet-5-5` と `claude-haiku-5-5` であり、aliasやdiscovery専用の架空modelは許可しない。同じrequest形でもmodelごとにpolicy fileを分け、別々のreview単位とする。CLI が送る認証 header、`anthropic-beta`、telemetry/SDK header は上流へ転送しない。model API relay は JSON に記載した `request_headers` のみを再構成し、実認証をrelay側で追加する。

model IDとretirement予定は2026-11-14にClaude Platform公式の[Models overview](https://platform.claude.com/docs/en/models/overview)で確認した。4.6以降のdateless IDがaliasではなく固定snapshotである根拠は[Model IDs and versioning](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions)による。modelを変更する場合は、新しいpolicy fileのreview、native discovery、proof、LaunchPermitをすべて再実施する。

field、path/query、value type、tool schema、固定 header のいずれかが変わった場合はfail-closeとし、ファイル更新は差分をレビューしてから行う。

`claude-code-2.1.323-macos-system-paths.json` は、このCLI版がmacOSで参照し得るorganization-wide `CLAUDE.md`、managed settings/MCP、machine/user MDMのsystem側パスと、Tempestが依存するSeatbeltファイルを列挙する。`{USER}` はrunnerの実効uidから解決し、managed pathは起動時に不在、Seatbeltファイルは実行時hashをprofileへ束縛する。この一覧は公式に文書化された既知の高優先度設定・指示源が混入していないことを保証するが、CLIの全file accessを独立にtraceして網羅性を証明したものではない。

managed settingsの場所と優先順位はClaude Code公式の[Managed settings](https://code.claude.com/docs/en/managed-settings)、organization-wide指示は[Memory](https://code.claude.com/docs/en/memory)を根拠とする。Tempestはnon-Anthropic `ANTHROPIC_BASE_URL` を固定するため、同文書の仕様上server-managed settingsは取得されない。user/project/local settingsは空のprivate HOME/CWDと`--setting-sources ""`で除外する。

macOS `system.sb` は `cfprefsd` とのMach通信を許可するため、MDMをfile denyだけでは制約しない。TempestのSeatbelt profileは`com.anthropic.claudecode` domainへの`user-preference-read`を明示拒否し、machine/user MDM plistの不在検査と組み合わせる。通常file accessは専用jailだけを許可する。これらは別々の境界であり、一覧外の設定源が存在しないことをfile deny単独では主張しない。

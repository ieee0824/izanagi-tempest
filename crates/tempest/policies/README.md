# Native CLI model request policies

ここに置く JSON は、native CLI の discovery 結果から実行時に自動生成する許可一覧ではない。CLI version と provider protocol ごとにレビューし、正式な acceptance で完全一致を要求する契約である。

`claude-code-2.1.323-anthropic-messages.json` は Claude Code `2.1.323 (Claude Code)` の `anthropic-messages` 契約を固定する。CLI が送る認証 header、`anthropic-beta`、telemetry/SDK header は上流へ転送しない。model API relay は JSON に記載した `request_headers` のみを再構成し、実認証をrelay側で追加する。

field、path/query、value type、tool schema、固定 header のいずれかが変わった場合はfail-closeとし、ファイル更新は差分をレビューしてから行う。

`claude-code-2.1.323-macos-system-paths.json` は、このCLI版がmacOSで参照し得るmanaged settings/MCP/MDMのsystem側パスと、Tempestが依存するSeatbeltファイルを列挙する。managed pathは起動時に不在、Seatbeltファイルは実行時hashをprofileへ束縛する。専用jail外の未列挙パスをCLIが読めないことはSeatbeltが保証し、この一覧は既知の高優先度設定源が混入していないことを保証する。

managed settingsの場所と優先順位はClaude Code公式の[Managed settings](https://code.claude.com/docs/en/managed-settings)を根拠とする。Tempestはnon-Anthropic `ANTHROPIC_BASE_URL` を固定するため、同文書の仕様上server-managed settingsは取得されない。user/project/local settingsは空のprivate HOME/CWDと`--setting-sources ""`で除外し、system側の既知パスは上記一覧、一覧外へのfile accessはSeatbeltでそれぞれ独立に制約する。

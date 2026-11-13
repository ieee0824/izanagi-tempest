# Native CLI model request policies

ここに置く JSON は、native CLI の discovery 結果から実行時に自動生成する許可一覧ではない。CLI version と provider protocol ごとにレビューし、正式な acceptance で完全一致を要求する契約である。

`claude-code-2.1.323-anthropic-messages.json` は Claude Code `2.1.323 (Claude Code)` の `anthropic-messages` 契約を固定する。CLI が送る認証 header、`anthropic-beta`、telemetry/SDK header は上流へ転送しない。model API relay は JSON に記載した `request_headers` のみを再構成し、実認証をrelay側で追加する。

field、path/query、value type、tool schema、固定 header のいずれかが変わった場合はfail-closeとし、ファイル更新は差分をレビューしてから行う。

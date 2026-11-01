# M0 実測記録

実施日: 2026-11-01。状態: **未完了・VM 起動で停止**。M1 以降には進まない。

## 実行環境と結果

| 項目 | 実測値 |
|---|---|
| Izanagi | `izanagi 0.2.7` |
| QEMU | aarch64 / x86_64 とも `11.1.2` |
| 設定 | `tools/m0/izanagi.example.toml` |
| 設定 SHA-256 | `a9f4aca04bfc8774e1ae2cbfde1038c04506343a35baf7ec9204ab0219bc5222` |
| 制限 | QEMU / vm-agent、認証必須、`restrict_network=true`、空 cwd の読み取り専用共有 |
| 前提確認 | バージョン取得成功 |
| `up --pcap` | 終了コード 1、`Operation not permitted (os error 1)` |
| 後処理 `down` | 終了コード 1、「izanagi は起動していません」 |

起動拒否の具体的な箇所は未特定。イメージは `default` 指定で、ハッシュ・コミットは
未固定のため、今回の記録は起動前の調査結果としてのみ扱う。
認証を無効化したり、ネットワーク制限を解除したりする回避は行っていない。

## 証跡

ローカルの非公開ディレクトリに保存。再実行時は別の出力先を使う。

- `/private/tmp/tempest-m0-preflight-20261101/summary.json`
- `/private/tmp/tempest-m0-boot-20261101/summary.json`

収集 JSON はコマンド、開始・終了時刻、終了コード、標準出力・標準エラーを含む。
キーの値は収集しない。ログや PCAP は点検なしにリポジトリへ追加しない。

## 未確認と再開条件

loopback の syscall・PCAP、API の成功・403・501、ホストツール隔離、
cwd と MCP セッションの対応、共有マウント、時計の出どころはすべて未確認。
Izanagi と QEMU が動作可能な環境で起動失敗の原因を確認し、イメージを固定して
収集ツールを再実行する。その後、IMPLEMENTATION.md 9.1 の検証を行う。

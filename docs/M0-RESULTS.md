# M0 実測記録

実施日: 2026-11-01。状態: **未完了・再ビルド後の起動と loopback syscall 発生を確認**。M1 以降には進まない。

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

## 再ビルド後の実測(利用者提供ログ)

初回収集とは別に、利用者がホスト・Debian イメージを再ビルドして同じ設定で実行。
以下は会話に提供されたログの要約で、生ログ・イメージのハッシュはまだ回収していない。
再ビルド後のバイナリを初回のバージョン・設定記録と混同しない。

| 項目 | 観測結果 |
|---|---|
| 起動 | 初期 handshake timeout の後に起動成功(PID 17128) |
| 実行ユーザー | uid / gid 1000 `izanagi`、追加グループなし |
| ツール探索 | PATH 上に curl・python3。aws・tcpdump・iptables・lws・doas は見つからず(未インストールとは断定しない) |
| loopback HTTP | Python のサーバー・クライアントで 127.0.0.1:57103 に接続し 200 OK |
| syscall | 20:05:56 頃、PID 569 の execve・bind・connect・sendto・recvfrom とスレッド 570 の送受信を記録 |
| 宛先・接続結果 | `connect() → unknown (entry)`。IP・ポート・戻り値はログにない |
| 警告 | id / date に Unknown process 警告。ツール探索の操作であり逸脱とは数えない |

この実測で確認できたのは syscall 発生の観測まで。宛先付きの接続検知、
LWS の認可判定、ゲスト PCAP の取得成功は確認できていない。

## ソース確認

ローカル Izanagi ソース HEAD: `d453baa121ddd08e2a84b8d36e88b8eb87d3b8ce`。
これは参照したソースの識別子であり、実行中のバイナリ・イメージとの一致は未確認。

- `izanagi-ebpf/src/main.rs` の `sys_enter_connect` → `emit_event` は数値引数を保存するが、
  sockaddr の内容を展開しない。通常の connect 終了イベントも収集しない。
- `src/ebpf_tracer.rs` の `convert_raw_event` はネットワーク宛先を `SyscallArg::Addr` に変換しない。
- `src/rules/network_allowlist.rs` は Addr がある場合に宛先を判定するため、この経路では検知できない。
- `src/log_formatter.rs` は受け取った引数と結果を表示する。表示省略だけの問題ではない。
- behavior 観測には別の TCP アドレス収集経路があるが、今回の通常ログでは未使用・未検証。

## 設計への反映と残る検証

記録プロキシを API 結果の第一証跡にし、backend 接続をファイアウォールで遮断する。
拒否試行はファイアウォールの拒否記録で取得する設計に変更した。収集方式は未実装・未検証。
PCAP は補助証跡とし、拒否パケットやログがないことを逸脱ゼロの根拠にしない。

残る項目は API の成功・403・501、IPv4 / IPv6 の迂回遮断と拒否記録、ゲスト PCAP、
ホストツール隔離、cwd と MCP セッションの対応、共有マウント、時計の出どころ。
バイナリ・イメージのハッシュとビルド元コミットを固定・記録し、IMPLEMENTATION.md 9.1 に従って検証する。

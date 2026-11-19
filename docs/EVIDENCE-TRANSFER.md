# Export証拠の有限転送予算

#64のLinux large001では、32KiBの逐次fetchが約300秒でAPI 1件とPCAP 1697件が完了した一方、59,299,901 bytesのPCAPを全回収できなかった。
これは固定環境の観測であり、律速原因や任意環境の最低速度を証明しない。元runの失敗と録画dropは変更しない。

hostはwire v1の32KiB chunk、64KiB固定暗号化返信、既存のfileサイズ上限とoffset/length/hash検査を維持する。
file開始時の絶対期限は次の予算とexport全体の残予算の短い方に固定し、進捗で延長しない。

```text
file予算 = min(600秒, 30秒 + ceil(file bytes / 32768) × 250ms)
export全体 = collection開始から600秒
```

64MiBでは542秒、large001の59,299,901 bytesでは482.5秒となる。4 chunks/秒に相当する余裕を置くが、完了を保証するものではない。
複数fileがそれぞれ新たに600秒を得ることはない。期限切れ・不確定RPC・不正chunkでは成功receiptを出さず、既存の破棄/partial cleanup契約を使う。
期限検査とtimeoutは次のfetch開始と管理RPC待ちに適用する。同期write/sync_all/renameは非同期timeoutで強制中断されず、600秒はディスク停止までを含むhard wall上限ではない。実プロセス寿命の上限は別のunit回収で検査する。
この期限は証拠転送だけを対象とし、起動・agent・export finalization・VM回収を含む試験driver/unitの全期限とは別である。
新実機試験ではdriver720秒/unit1800秒の範囲と実elapsedを別に確認する。

収集順はmanifest.json → api.jsonl → capture.pcapとし、PCAP転送で失敗しても先に認証・hash照合したmanifestを保持する。
全file verifiedまでcollection.completeにはしない。manifest.complete=falseを転送成功だけでtrueへ変換しない。
#65の録画drop、management停止receiptの意味、全route/全期間の未証明は別課題のまま残す。

検査は予算の有限性・実測条件に対する余裕・後続fileが全体期限を延長できないこと、実collect_fileの期限切れ時にfetchを開始しないことと、既存chunk認証/整合性を扱う。
固定VMでの上限近傍の配送とmanifest先行保持は別の実測gateであり、単体テストだけで完了扱いにしない。

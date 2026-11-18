# bootstrap build 003: image生成成功と終了属性の観測不足

2026-11-18、room #16391後に[固定command](LINUX_BOOTSTRAP_BUILD_003_PLAN.md)を単発実行しました。
build client exit0でimageを生成しました。probe起動/full Tempest guest/credential/live-callは行っていません。

## ビルド結果

observer37384を先行し、build55652を開始しました。unitは003、InvocationIDは
`0b04c9cfd5284f6fb63e54df8fb1599d`、cgroupは
`/system.slice/tempest-izanagi-bootstrap-build-003.service`です。
開始前に13入力hash/mode・unit未使用・UID999残留なし・3port空き・新output不在を確認しました。

SSH接続、agent/helper配置、helper後のagent service登録、root password lockを通過しました。
最終化時の`IZANAGI_IMAGE_SECURITY_OK`、Packer artifact成功、
systemd-runのResult=success/code=exited/status=0を同じclient logへ記録しました。
service runtimeは1min49.535sです。これは最終化時の検証であり、image再起動後の検証ではありません。

完成fileは`/var/lib/tempest-izanagi-bootstrap-build-003/work/output-x86_64/alpine-x86_64.qcow2`、
102,367,232 bytes、SHA256は
`9650b1c4d1dafd70cb608abda0bff4c9fa1cd6485adb18ae0f186d9bd5d96211`です。
まだ専用userのwork内にあるため、次の起動前にはroot所有・非書換え配置とhash再照合が必要です。

## 観測と回収、終了属性の不足

125sampleで実listenは127.0.0.1:18081/22221/5901、QEMU network引数も固定設定と一致し、
非loopback listenは検出しませんでした。1秒samplingの全網羅性は主張しません。
build client exit0、observer exit0ですが、最終rowはGC後のnot-found/Invocation空でした。
同Invocationのactive状態までは保存できたものの、terminalのExecMainCode/Status属性は保存できていません。
従ってobserver exit0やunit不在を同Invocationのterminal証拠とは扱いません。

別途journalctl JSONからUNIT=003、
`MESSAGE_ID=7ad2d189f7e94e70a38c781354912448`（Deactivated successfully）、
同じ`INVOCATION_ID=0b04c9cfd5284f6fb63e54df8fb1599d`の記録を回収しました。
これは同Invocationの正常deactivation記録であり、取り逃したsystemctl属性の再取得とは区別します。
client exit/result、journal、image最終化、回収を別証拠として監査へ提出しました。

終了後にcgroup不在、UID999残留なし、3port閉鎖、001/002/003全snapshot入力hash不変を確認しました。
observerは今後not-found/Invocation欠落なら証拠不足の非0にする修正を加え、
GCを成功扱いしない負例を含むPython全6testが成功しました。既存観測fileは書換えていません。

## private保持証拠

| 証拠 | SHA256 |
| --- | --- |
| /tmp/tempest-bootstrap-build-003.log | 56f63179e13e1bdb6e1f6346b440a6e0b4bc71a490ab277bad4090851534853c |
| /tmp/tempest-bootstrap-build-observation-003.jsonl | c9cb71b785000413fa62c7e2911ccc4860fc1d390357c87d1dd3f5f6cd94b432 |
| /tmp/tempest-bootstrap-build-003-journal.json | 166a27cef6e9dc4f4992088922dcfa9aead3c2555bd159c5dd9d76c1a0f20aed |

001/002の途中imageと証拠も保持しています。観測不足を埋めるための無断再buildはしません。
次はこの証拠の監査、root所有artifact配置、最小boot用commandの具体確認です。

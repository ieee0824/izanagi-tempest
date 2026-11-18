# 固定boot002: 認証Ready・guest UID・down成功

2026-11-18、room #16427の指示後に[固定command](LINUX_IZANAGI_BOOT_002_PLAN.md)を1回実行しました。
固定Alpine/idの最小経路が成功しました。本番VM境界やfull Tempest guestの受入へは一般化しません。

## 実行と固定診断

observer62743先行、boot44375、unit `tempest-izanagi-bootstrap-boot-002.service`、
InvocationID `6923093b68f04f298922ed2d6ce51f32`、MainPID257223で開始しました。
直前に3artifact hash/mode・unit未使用・UID999残留なし・tmp/evidence/share空・secret metadataを確認しました。
client exit0、service runtime11.638秒、固定stdoutは次のとおりです。

```json
{"down_returned_ok":true,"exec_exit_code":0,"exec_status":"matched","exec_stderr_present":false,"exec_stdout_matches":true,"guest_uid_matched":true,"ready":true}
```

認証Ready、固定`/usr/bin/id -u`のexit0/stdout `1000\n`/stderr空、down戻り成功を確認しました。
初期接続resetによる内部handshake再接続が3回logにあります。別commandによる再bootではありません。
全command許可やbasename許可へ広げず、固定id allowlist入りimageと段階診断付きharnessを使用しました。

## 選別引数・終了証拠・独立回収

対象QEMU PID257228の選別引数は次のとおりです。fw_cfgや全argvは出力していません。

```text
-netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:36935-:9001
-drive file=/var/lib/tempest-izanagi-bootstrap-002/base.qcow2,format=qcow2,snapshot=on
-fsdev local,id=fs0,path=/run/tempest-izanagi-bootstrap-002/share,security_model=mapped-xattr,readonly=on
```

25sample（11:20:02.201921〜11:20:26.778252 UTC）で非loopback listenは検出しませんでした。
sampling間の短時間socketや、外部到達拒否の実通信成功を主張しません。

ExecStopPostは同Invocation、SERVICE_RESULT=success、EXIT_CODE=exited、EXIT_STATUS=0、
systemctl ExecMainCode1/ExecMainStatus0を保存しました。snapshotはdeactivating/stop-postで最終terminalとは区別します。
observerはGCで最終属性を取り逃し、unknown/exit1でした。不在を正常terminal証拠にしていません。
最終journalは同UNIT/Invocation、trusted PID1/UID0/current boot ID、正常deactivation MESSAGE_IDを確認しました。
client終了値・ExecStopPost・trusted journalを別証拠の組合せとして提出します。

独立確認でcgroup不在、UID999残留なし、agent36935閉鎖、tmp/share空、
両boot artifact/image hashと旧exit証拠hashの不変を確認しました。
証拠保全・独立回収後、新dummy.secret固定fileだけを削除し非存在を確認しました。
内容・hashは出力せず、旧run/evidenceも変更していません。

## private保持証拠

| 証拠 | SHA256 |
| --- | --- |
| /tmp/tempest-izanagi-boot-002.log | 52a8cce53647a1c8c15689eaec931e240ad9621ff3c7b133bb2ab27c4bea3c82 |
| /tmp/tempest-izanagi-boot-observation-002.jsonl | 44ac8fd20d3320656ebc1bfda4f90e56b6a4b72dc3cb40c095d877a0cdd33e29 |
| /tmp/tempest-izanagi-boot-002-journal.json | 343aa672e08b65c4e9ca4a580503f584d6053c6c4355f16c61119e9d38359f8a |
| /run/tempest-izanagi-bootstrap-002/evidence/exit-status.json | 013841bc7d373dbd4d9cb8930dbfe064d30afd2d3fe1e283c85787dc1a52fe03 |

外部通信拒否の実測、owner/firewall/doas/mailbox/control/clock/timeout、eBPF/HTTP、
full Tempest guest/派生Debian、credential/live-callは未達・未着手です。
再試行/fallbackや次のfull buildは結果監査前に行いません。

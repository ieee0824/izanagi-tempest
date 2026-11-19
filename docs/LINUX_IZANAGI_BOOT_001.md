# 最小boot001: Ready成功・guest UID確認不成立

2026-11-18、room #16404の監査指示後に[固定command](LINUX_IZANAGI_BOOT_RUN_PLAN.md)を1回実行しました。
最小bootの全受入は未達です。再実行・fallback・full guest/credential/live-callは行っていません。

## 実行と診断

observer42807を先行、boot client34830、unit `tempest-izanagi-bootstrap-boot-001.service`、
InvocationID `9e5c5dc986bf415ab5c877e8d720de0c`、MainPID253460で開始しました。
開始前に3artifact hash/mode、unit未使用、UID999残留なし、tmp/evidence/share空、secret metadataを確認しました。

固定stdoutは次のとおりで、client exit1、service runtime9.645秒でした。

```json
{"down_returned_ok":true,"guest_uid_matched":false,"ready":true}
```

認証Readyには到達しましたが、guest UID1000の固定Exec受入は不成立です。
途中に接続resetのhandshake再接続が1回logへ出ました。別boot commandを再実行したものではありません。
現在のharnessはExecのtransport/exit/stdout/stderr各失敗をboolへ集約するため、
今回のExec応答が拒否・非0・UID不一致のどれかはこの証拠だけでは確定できません。

source照合ではagentはIZANAGI_ALLOWED_COMMANDS未設定時にcommandをfail-closed拒否します。
固定Alpine template/OpenRC initと派生helperにはallowlist設定がありません。
従ってallowlist欠落は有力な説明ですが、今回の実Exec拒否理由の直接記録とは区別します。
次の修正案はguestで`/usr/bin/id`だけを明示許可し、harnessに非秘密の段階診断を加えることです。
ALLOW_ALLや任意commandへ広げません。image/harness変更と次attemptは再監査します。

## 実引数と回収

対象QEMU PID253465の選別引数を記録しました。fw_cfgや全argvは記録しません。

```text
-netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:33545-:9001
-drive file=/var/lib/tempest-izanagi-bootstrap/base.qcow2,format=qcow2,snapshot=on
-fsdev local,id=fs0,path=/run/tempest-izanagi-bootstrap/share,security_model=mapped-xattr,readonly=on
```

22sampleで非loopback listenは検出しませんでした。外部到達拒否の実通信は未検証です。
ExecStopPostは同Invocation、main code=exited/status1、Result=exit-codeを保存しました。
そのsnapshotはdeactivating/stop-postで、最終terminalとは区別します。
observerの最終rowは同Invocationのfailed/ExecMainCode1/Status1、cgroup PID空でした。
observerはexit0（観測成功）であり、boot成功ではありません。

trusted journalは同Invocation、PID1/UID0/current boot IDを照合して保存しました。
別確認でもcgroup不在、UID999残留なし、agent33545閉鎖、tmp/share空、全3artifact/image hash不変でした。
証拠保全と独立回収後に固定dummy.secretだけを削除し、非存在を確認しました。
内容・hashは一切出力していません。evidence/logや過去imageは保持しています。

## private保持証拠

| 証拠 | SHA256 |
| --- | --- |
| /tmp/tempest-izanagi-boot-001.log | 399278c5418d1e0b378039726fbf70ef02821f614e5adb86c61a2bec2fce1b77 |
| /tmp/tempest-izanagi-boot-observation-001.jsonl | 784e24d0e99f8b4fb2ee31609ce3b4c68d6c2cdeb684d0614178aa1062372848 |
| /run/tempest-izanagi-bootstrap/evidence/exit-status.json | c03b5aeab76e49cc320533e9ba7b958cb3fb4e8b4a7da8d3d292b82ea9441f76 |
| /tmp/tempest-izanagi-boot-001-journal.json | 36ed6c8d91cada880d5e84932eb59324c44c417065758479e17af335114cb3a7 |

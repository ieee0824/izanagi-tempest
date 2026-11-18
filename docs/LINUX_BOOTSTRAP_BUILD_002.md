# bootstrap build 002: 既存lockへのpasswd再適用で失敗

2026-11-18、room #16383の指示後に[固定command](LINUX_BOOTSTRAP_BUILD_002_PLAN.md)を1回実行しました。
attempt001のpartition失敗箇所を通過しSSH接続・agent/helper uploadまで進みましたが、完成imageは得られていません。

## 実行と直接診断

observer49994を先行し、build56898を開始しました。InvocationIDは
`1273188bfd544ebe8e8181cda5e9b9fa`、unitは`tempest-izanagi-bootstrap-build-002.service`です。
13入力hash/mode、unit未使用、UID999残留なし、固定3port空き、新output未存在を直前確認しました。
固定bindとQEMU network引数を実測し、117sampleで非loopback listenは検出しませんでした。

build logは`Connected to SSH!`とagent/lock-down/verify/helperのupload後、
`passwd: password for izanagi is already locked`、script exit1を記録しています。
helperの`adduser -D`後に`passwd -l izanagi`を実行しており、既存lockへの操作が非0となって
`set -e`で停止しました。後続fw_cfg確認・agentサービス設定・最終lock-down/verifyには未到達です。

## 終了と回収

build client exit1、observer exit0（観測正常終了）。service runtimeは1min46.086sです。
最終sampleは同InvocationID、unit failed/Result=exit-code/ExecMainCode=1/ExecMainStatus=1、
cgroup PID空でした。別確認でもcgroup不在、UID999残留なし、3port閉鎖、
attempt001/002の両snapshot全入力hash不変でした。
Packerの`-on-error=abort`でplugin側cleanupを省略しても、外側systemd control-groupで終了しています。
再実行・fallback・probe起動は行っていません。

## private保持証拠

| 証拠 | size | SHA256 |
| --- | --- | --- |
| /tmp/tempest-bootstrap-build-002.log | 4274 | 4017d2d7c1bb4606000f6f62c6d0fb481e9e38eb714b567a28c1d31d097678bb |
| /tmp/tempest-bootstrap-build-observation-002.jsonl | 90103 | 109b1eafdca6aa61128686c25840e180ec47c0ec628b8b67b57d5afa13e5b9c6 |
| attempt002 work/output-x86_64/alpine-x86_64.qcow2 | 99418112 | a09b67a6c4a78735ff2d8efa4442087b3ff7662ae1bbdbf9b24da8f495e37292 |

途中imageは成功入力として使わず保持します。unit resetや証拠削除は行っていません。

## 修正準備

helperを、既存lockへ`passwd -l`を再適用する代わりにshadowの該当entryが
一意で先頭`!`/`*`のlocked状態であることをawkで確認する形へ変更しました。
shadow内容やhashは出力しません。空・未lock・不在・重複は拒否します。
実helperのpredicateを使う7fixtureの検証と`sh -n`が成功しました。
これはguestでの修正成功の証明ではなく、次attemptの定義・snapshot・unit・command再監査が必要です。

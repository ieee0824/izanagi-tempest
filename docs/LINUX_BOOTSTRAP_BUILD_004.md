# bootstrap build004: 固定id allowlist入りimage生成

2026-11-18、room #16417の指示後に[固定command](LINUX_BOOTSTRAP_BUILD_004_PLAN.md)を1回実行しました。
client exit0でimageを生成しました。root artifactの置換やbootは行っていません。

## 実行と生成物

observer91610を先行、build73851、unit004、InvocationID
`d51b49c657b946c59c01ea0b2be68ee8`、MainPID256259で開始しました。
開始前に13入力hash/mode・unit未使用・UID999残留なし・固定3port空・新output不在を確認しました。
SSH接続、guest provision、agent service登録、最終`IZANAGI_IMAGE_SECURITY_OK`、Packer artifact成功を記録しました。
service runtimeは1min49.491s、client logはResult=success/code=exited/status0です。

生成fileは`/var/lib/tempest-izanagi-bootstrap-build-004/work/output-x86_64/alpine-x86_64.qcow2`、
101,515,264 bytes、SHA256は
`7ad583f9f1514899e4f8c88b7f71609a5c0f6b76e0e213a01ef82d51f74978e5`です。
helperが固定`/usr/bin/id`だけのOpenRC conf.d設定を生成する入力でbuildしました。
その起動環境への実到達とguest UID成功は次bootの未検証事項です。

## 観測不足と独立回収

122sampleで対象listenは127.0.0.1:18081/22221/5901のみ、非loopbackは検出しませんでした。
GC後のnot-found/Invocation空になったため、observerは修正どおりunknown/exit1でした。
systemctlの同Invocation terminal属性は未保存のままで、不在を成功にしていません。

別途journalの同UNIT/Invocation、trusted PID1/UID0/current boot IDを照合し、
正常deactivationのMESSAGE_ID `7ad2d189f7e94e70a38c781354912448`を保存しました。
client単発実行/開始unit/継続観測とtrusted journalは別証拠の組合せとして提出します。
開始/終了のcurrent boot ID実値は`30389abc903c40ae89a5c6268ec1c432`、
同Invocation `d51b49c657b946c59c01ea0b2be68ee8`です。
trusted source時刻は11:11:54.429822〜11:13:43.920985 UTC、差109.491163秒で、
client表示109.491秒と丸め誤差内で一致しました。
qemu-img infoもread-onlyでqcow2/virtual2GiB/backing fileなし/corrupt=false/dirty=falseを確認しました。

終了後にcgroup不在、UID999残留なし、固定3port閉鎖を独立確認しました。
001〜004の全snapshot入力と既存boot001 root artifactのhashは不変です。
既存image/証拠/failed unitを削除・resetしていません。再試行/fallback/bootは行っていません。

## private保持証拠

| 証拠 | SHA256 |
| --- | --- |
| /tmp/tempest-bootstrap-build-004.log | 6ea468c8e9c00302a6fdcc683a5d5e896646886ccff1a49383eeffb38e030725 |
| /tmp/tempest-bootstrap-build-observation-004.jsonl | 1c0fda2d834ea2e2160bf8ab147757fbeeda01050da4f0d4a2ad88fce15faf14 |
| /tmp/tempest-bootstrap-build-004-journal.json | 97b53157acf4bf81fb9d342e94015b996be5c18af2433b2a298e58d99b027913 |

次は新imageと段階診断付きharnessを別root配置へ固定し、新しいboot002のunit/run/recorderを監査します。

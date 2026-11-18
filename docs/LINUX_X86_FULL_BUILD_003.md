# Linux x86 full image build003 成功と回収

2026-11-18、room #16509 の監査後、[固定計画](LINUX_X86_FULL_BUILD_003_PLAN.md)を一度実行した。10秒のboot_waitで正しいkernel引数到達と無人インストール、派生Debian full image生成に成功した。guest runtime境界や正式比較の受入とは区別する。

## 入力と起動

全26input hash/mode/owner、helper hash/shared=1、serial/debug/output不在、新unit未使用、uid999残留なし、3port空、free58800185344 bytesと旧001002証拠不変を直前確認した。observer10130→finite read-only frame89653→caller69678の順に開始。unitは `tempest-izanagi-bootstrap-image-003.service`、Invocation `c6f14dd35ebb4525ab301aae427d76e1`。

frame helperはexit0、初期BIOS menu/speech開始28秒のPNGを保存（SHA `4808651e57c2004518191c0b2c969e4dbc81183244da5dc3ded27d31637c9cd7`）。Packer debug選別eventはQEMU exec12:22:36、bootwait12:22:38、Typing12:22:48、PNG保存mtime12:22:40.028884 UTC。入力が30秒自動speech期限に間に合い、serialの実kernel command lineに次が到達した。

```text
BOOT_IMAGE=/install.amd/vmlinuz console=tty0 console=ttyS0,115200n8 auto=true priority=critical preseed/url=http://10.0.2.2:18082/preseed.cfg initrd=/install.amd/initrd.gz ---
```

実QEMU281476のcwdは専用work003に一致し、serial/debugは通常file0600。serialでDHCP、Installing the base system、Select and install software、Finishing the installationの表示を選別確認した。HTTP preseed GETの独立記録は未取得であり、その不存在を主張しない。

## 終了証拠の区別

caller exec69678は途中で143の終端となったが、systemctl/observerで同Invocation active/runningが継続していることを確認した。fd1/fd2はprivate caller logへ直接保持され、unitを再実行せず追跡した。caller143をservice失敗や成功の根拠にしていない。

private最終logはPacker finished5min21s、`IZANAGI_IMAGE_SECURITY_OK`、service Finished with result: success / code=exited/status=0、runtime5min21.787sを記録。別のtrusted PID1/UID0/currentboot journalは同Invocationで12:27:56.371218 UTCにDeactivated successfullyを記録した。

observer10130はGC後に同Invocation終端属性を捕捉できずexit1でunknown。この結果を成功へ読み替えず、同名unitのGC後のデフォルトResult/ExecMainStatusも終了証明に使わない。独立の最終log、同Invocation trusted journal、生成物、回収証拠を照合した。

[結果JSON](LINUX_X86_FULL_BUILD_003_RESULT.json)へ334 observations、全区間external listener false、最後の観測、trusted journal、入力不変、private各ログ/PNG/imageのhashを保存した。独立確認でcgroup消失、uid999 processなし、HTTP18082/SSH22222/VNC5902全閉。全26inputと旧001002のinput/証拠SHAは不変。追加stop/killは不要だった。

## 生成物と未検証範囲

`/var/lib/tempest-izanagi-full-build-003/work/output-debian/debian-x86_64.qcow2` は2145124352 bytes、SHA-256 `5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e`、uid999/gid988/mode0600。既存qemu-img infoを非起動で取得した。原本と証拠はprivate領域に保持している。

この成功は固定artifactからの無人image buildとlock-down検査の範囲。新imageのIzanagi認証boot、実installed package/loaderとのABI照合、eBPF load/trace/HTTP capture、M3 owner/firewall/doas/mailbox、外部通信拒否、credential/livecallは未検証。次の実VM試験は生成物/定義/証拠の監査と具体計画の後に行う。

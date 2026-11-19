# Linux image smoke001: 初回失敗と独立回収

room #16551 の監査後、[v2固定計画](LINUX_X86_IMAGE_SMOKE_001_PLAN.md)を一度実行した。VMは再試行していない。初回smokeの受入は未達。

## 起動と失敗

直前に全1304input/外部runtime、v1と旧full003までの証拠不変、出力/鍵/exit/caller-observer log不在、新unit未使用、uid999残留なし、free52257779712 bytesを確認した。observer49792を先行しcaller25131を開始。unit `tempest-izanagi-image-smoke-001.service`、Invocation `96b2852f82474fc9a282c965481ee4b0`、host boot ID `30389abc903c40ae89a5c6268ec1c432`。

観測したQEMUはPID284079/starttime35042610。restrict=on、127.0.0.1:39833→9001、固定image snapshot=on、mapped-xattr/readonly=onを記録した。しかしfsdevのpathは絶対pathではなく `.` で、observerは固定共有path条件を満たさないとしてexit1になった。実QEMU cwdを今回は採取できていないため、source上のcwd設定だけで正しい実体を実測済みとはしない。observerは早期終了しており、全VM lifetimeの単一性も未確定。

本体はinventory/image_manifest/build_guest_bindingを通過後、izanagi_installed_artifactsのguest Python commandでexit1。hash比較の不一致ではなく、actorが `/usr/local/bin/izanagi-agent` をread_bytesした時のPermissionError/EACCESだった。root側binaryをactorに読ませる追加checkの前提が誤っており、read permissionを緩めて解決しない。agent/HTTP/eBPF実hashが既存guest metadataに含まれない点は未解決として残す。

nonce trace probe、runtime ABI inventory、M3 claim/seed/200-403-501/HTTP-PCAP/各境界の本検査には到達していない。up/exec開始が成功したことを、nonce/PID/pathの実採取や全smoke成功に読み替えない。

## 終了と証拠

caller25131とobserver49792はともにexit1。ExecStopPostは同Invocationのservice_result=exit-code/exit_status1をstop-post中に保存し、最終systemctlもloaded/failed/ExecMainStatus1を保持した。trusted PID1/UID0の同Invocation/currentboot lifecycleも別に採取した。

[結果JSON](LINUX_X86_IMAGE_SMOKE_001_RESULT.json)へ観測row、最後のunit、exit recorder、checkの選別状態、private各fileのhash、trusted UNIT/MESSAGE_ID等を保存。private原本のsummary/up stdout/stderr/CLI events等は公開せず、transport key値や単体hashも記録していない。選別private log8件にtransport keyの一致はなかった。key fileはprivateで結果監査まで保持し、room #16557の監査後に当該fileだけ削除して非存在を確認した。値/単体hashは読まず、原本log/summary等は保持した。

独立確認でunit cgroup消失、uid999processなし、agent port39833閉。実行がすでにfailed/回収済みだったため追加stop/killは不要。全1304input/hash/modeとv1、旧full001002003証拠は不変。symlink targetとdirectoryのowner/modeも再確認した。この実行はlocal dummy準備のみで、外部credential/API/model比較は利用していない。

次は実cwdに束縛した共有path解決と、actor権限を緩めずroot-owned実artifactを検証できる証拠経路を修正する。既存image/旧root入力/失敗原本は保持し、新VMやfallback tracerを起動しない。修正後は別attemptとして具体入力を再監査する。

# #13 配送・露出の証拠表

## 固定条件と判定範囲

対象は固定Izanagi `16d0b55947006a166cfa29dcb8bfe71f65f8c36a`、LWS
`2c0ea463f334f10a562e54f1cdc7ba8a474029e2`、[full003 image](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_FULL_BUILD_003.md)
のLinux x86構成。dummy入力だけを使い、restrict usernet/read-only mapped 9p/snapshotを維持する。
ホストUID999のcontrollerとguest UID1000のactor、guest root consumerの権限を区別する。
以下の実測は保存RESULTとcollector/sourceの照合であり、MacからLinux実ファイルの再測定ではない。
古いarm64の報告は[M3記録](M3-IMAGE.md)へ分離する。

## 方向・方式・上限・残留

| 対象/方向 | 選んだ方式と理由 | 上限・障害時処理 | 根拠 |
|---|---|---|---|
| tokenのclaim返信→host | root native stdoutをconsumerがAES-GCM暗号化し、doasは保存暗号文だけ返す。IDの秘密性に依存しない | 応答は固定65536B pad。再取得は同IDの同暗号文。claim再発行は拒否 | dispatcher/transport、smoke002 known_id_claim/claim_nonreissue |
| 管理token host→native | root専用mailbox内のauthorization、root consumerからnative stdin。固定execはstdin/FDを配送しないためexecにtokenを載せない | private inbox内で一時fileを発行しowner/mode確定後rename。実mapping不成立なら起動拒否 | image/README配送契約、smoke002 mapping/UID衝突の正負例 |
| seed/probe host→native | setup/probeはroot private request→root private input.json。native argvは入力pathだけ | serialized requestは8MiBまで。native入力はfinallyで削除。状態変更の応答不確定時は別IDで再送しない | transport/dispatcher、smoke002 seed/probe200/403/501、seed-loss001 |
| export/fetch guest→host | quiesce後root export、allowlist3fileを暗号化chunkで回収。hostがchunk/全体SHA・長さを検証 | chunk32768B、応答約88KiBで固定exec512KiB上限内。応答枠超過・不明はuncertain、未完partialは成功にしない | image/README、smoke002 export/API/PCAP、正常2run |
| 終了・途中失敗 | 通常・timeout・異常終了の子孫からprivate領域を隔離。export前barrier、VM廃棄後transient回収 | guest nonce/replyは使い捨てsnapshot内。hostの途中残留はprivateに限定、同run再開/再seedを拒否 | smoke002各90open拒否、正常2run/reset、seed-loss＋独立reservation001 |

nativeのstdin/file方式ではargvの総量を分割で回避する必要はない。argvには固定command/path/内容非依存IDを載せ、
request上限と応答枠を別に検査する。将来argv配送を加える場合、その1引数/argv+env総量の実測はこの表で保証しない。

## 場所・閲覧主体・目印の観測

| 場所 | 閲覧主体/境界 | 現在の観測値と証拠 | 未確認・制約 |
|---|---|---|---|
| host/guest mailbox・一時input | host controller、guest rootのみ。guest actorからread不可 | smoke002 root0700/file0600、readonly書込EROFS、UID衝突owner変換前後EACCES、既知IDのprivate request read拒否 | hostの別privileged主体や任意kernelへの一般化なし |
| guest root PIDのfd/environ/mem、LWS environ | guest actorからEACCES/EPERM | smoke002 root_proc_private_denied/lws_environ_denied | 内容を全PID・全期間採取した証拠ではない |
| doas入口・root native呼出 | actorはdeliverのみ。native/watch/shell代理実行を許さない | smoke002 doas_other/native/watch/tokenless_seed拒否、保存暗号文の反復/並列取得は安定 | native内部PIPEの実bytesをactor経路で観測したものではない |
| actorから見たPID集合のcmdline/environ/FD一覧 | guest UID1000。FD内容は読まない | [proc-exposure001](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_PROC_EXPOSURE_001.md)はbefore_claimの128件、controls3種成立、stream切詰め/error0 | PID集合が128超で停止し未合格。後2時点/最終scan未到達。全期間・短命nativeを保証しない |
| actorから見た3時点のPID集合 | guest UID1000、FDは一覧のみ | [proc-exposure003](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_PROC_EXPOSURE_003.md)：列挙132/113/116対象、2/1/1ページ、全requested対応。各時点vanished2を別集計、全controls成立、切詰め/error0 | 列挙後の新規process・短命native・FD内容・同時刻/全期間は未確認。個別helperのguest statは未測定 |
| native argv/env/stdin | source上、tokenはstdin、setup/probeはprivate path、envは固定PATH/audit ID | dispatcherのcommand/env構築とfinally削除を確認 | /proc cmdline、親shell、execve、env/FDの全実行・全期間の直接目印検査は未確認 |
| events/alerts rotations、up stdout/stderr | host private保存。公開は選別結果 | smoke002 host_logs_private_markers passed、実eBPF nonce/PID/path一致 | ログが記録しなかった経路の不存在証明ではない |
| host CLI exec stdout/stderr、失敗診断 | 新exec-evidence0700/各file0600。公開は件数/種別/leak有無 | [exec-exposure001](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_EXEC_EXPOSURE_001.md)は保存scan173exec/346stream・漏出0、expected-error読取7、metadata/権限整合を確認 | markerを再取得した独立再scanではない。host timeout0のため部分bytesはunit fixtureのみ。native PIPEとは別scope |

exec-evidenceの目印はdummy管理token/reply AES key/private payloadであり、許可されてagentへ渡るworker資格情報と混ぜない。
raw stream、目印値、鍵値を公開しない。host timeout部分出力の単体fixtureと実VMで起きたtimeoutは区別し、
今回の実測counterが0ならhost timeout経路を実測済みとしない。

## 保存証拠と残作業

- [smoke002](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_IMAGE_SMOKE_002.md) / [RESULT](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_IMAGE_SMOKE_002_RESULT.json): owner/doas/procアクセス拒否、親終了後の子、API/PCAP/ログ目印。
- [正常2run/reset](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_RUNTIME_NORMAL_001.md): primary/retestのfresh VMと回収。observer GC終端unknownは別trusted終了証拠と区別。
- [seed-loss001](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_RUNTIME_SEED_LOSS_001.md): 成功返信喪失→agent未開始→廃棄は確認。trial末尾の旧診断検査失敗は保持。
- [reservation001](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_RUNTIME_RESERVATION_001.md): 別検査でEEXIST、旧1537項目不変。旧trialの遡及合格ではない。
- [exec-exposure001](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_EXEC_EXPOSURE_001.md): 保存scanと173metadata/519private fileの整合、trusted終了・回収・1307入力不変。operation件数はdeliver読取を含み、状態変更の新規投入数ではない。

[proc-exposure001](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_PROC_EXPOSURE_001.md)はPID集合上限超過、[002](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_PROC_EXPOSURE_002.md)はVM起動前のxattr設定順序で失敗した。原本を保持し、遡及合格としない。001 collector元呼出し終端はunknownを維持する。
PR #57の有限ページ方式とPR #58のxattr→host chmod修正後、[003](https://github.com/ieee0824/izanagi-tempest/blob/f24b14e/docs/LINUX_X86_PROC_EXPOSURE_003.md)で3時点の限定観測を完了した。
各時点の観測区間は約178.192/100.300/105.498ms、wire bytes42112/35109/36562。全requestedの対応は全identityの生存/読取成功ではない。
保存列挙3frame/観測4pageから固定純粋summary関数で再計算し、元summaryとの完全一致を確認した。
exec180実行/360streamの保存中scanはleak0、540private fileの件数/byte/owner/modeを照合した。
collectorはmarkerを回収した独立再scanを行わず、Mac監査は保存source/RESULTの整合確認である。
observerはGC終端unknownのまま、同InvocationのExecStopPost exit0/trusted journalとcgroup/UID/port回収を別証拠とする。
公開helper2fileのhost通常単link/UID999:GID988/0444・元source一致と実xattr uid0/gid0/mode0100444は追補collectorで照合した。
個別helperのguest owner/modeの直接statは未測定であり、hostの設定・guest実読取・共有EROFSから直接測定済みへ読み替えない。

## 選定結果と関連実装

#3のtoken/seed/probe/exportはroot専用mailbox＋native stdin/private input path＋AES-GCM固定枠を採用する。
固定execのstdin/FD非転送を理由に秘密をargvへ移さず、host/guest owner・mapping・read-onlyとconsumer/doasの役割を#4の権限分離へ結び付ける。
#5のexport前quiesce/barrierと不確定seed時のdiscardを維持し、別ID再送や同run再開を行わない。
方式・上限・障害時処理の実装契約は[image README](../image/README.md)、[実装設計](IMPLEMENTATION.md#33-ハーネス専用操作をエージェントから守る)を参照する。
ホスト結合試験は暗号frame/状態機械の証拠、固定VMはdoas/owner/mappingと限定proc観測の証拠として扱う。

native PIPE、回収不能・強制競合、全route/全期間、HTTP sidecar・外部positive control・実モデル比較は未確認のまま残る。
この調査で選んだ配送方式と限定した証拠は、これらの受入gateの完了や正式モデルrunのeligibleを意味しない。

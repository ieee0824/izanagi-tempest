# #13 配送・露出の証拠表

## 固定条件と判定範囲

対象は固定Izanagi `16d0b55947006a166cfa29dcb8bfe71f65f8c36a`、LWS
`2c0ea463f334f10a562e54f1cdc7ba8a474029e2`、[full003 image](LINUX_X86_FULL_BUILD_003.md)
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
| native argv/env/stdin | source上、tokenはstdin、setup/probeはprivate path、envは固定PATH/audit ID | dispatcherのcommand/env構築とfinally削除を確認 | /proc cmdline、親shell、execve、env/FDの全実行・全期間の直接目印検査は未確認 |
| events/alerts rotations、up stdout/stderr | host private保存。公開は選別結果 | smoke002 host_logs_private_markers passed、実eBPF nonce/PID/path一致 | ログが記録しなかった経路の不存在証明ではない |
| host CLI exec stdout/stderr、失敗診断 | 新exec-evidence0700/各file0600。公開は件数/種別/leak有無 | PR #54の7試験でstderr漏出拒否・timeout部分bytes等を確認 | [exec-exposure001計画](LINUX_X86_EXEC_EXPOSURE_001_PLAN.md)の実VM試験は未実施。native PIPEとは別scope |

exec-evidenceの目印はdummy管理token/reply AES key/private payloadであり、許可されてagentへ渡るworker資格情報と混ぜない。
raw stream、目印値、鍵値を公開しない。host timeout部分出力の単体fixtureと実VMで起きたtimeoutは区別し、
今回の実測counterが0ならhost timeout経路を実測済みとしない。

## 保存証拠と残作業

- [smoke002](LINUX_X86_IMAGE_SMOKE_002.md) / [RESULT](LINUX_X86_IMAGE_SMOKE_002_RESULT.json): owner/doas/procアクセス拒否、親終了後の子、API/PCAP/ログ目印。
- [正常2run/reset](LINUX_X86_RUNTIME_NORMAL_001.md): primary/retestのfresh VMと回収。observer GC終端unknownは別trusted終了証拠と区別。
- [seed-loss001](LINUX_X86_RUNTIME_SEED_LOSS_001.md): 成功返信喪失→agent未開始→廃棄は確認。trial末尾の旧診断検査失敗は保持。
- [reservation001](LINUX_X86_RUNTIME_RESERVATION_001.md): 別検査でEEXIST、旧1537項目不変。旧trialの遡及合格ではない。

まずexec応答とexpected-error診断の限定実測を行い、この表の該当欄だけを更新する。
直接/proc観測とnative PIPE、回収不能・競合経路は実測/制約を個別に整理する。HTTP sidecar・外部positive control・
全route coverage・実モデル比較の検証を、この表だけで完了扱いにしない。#13はopenのまま追跡する。

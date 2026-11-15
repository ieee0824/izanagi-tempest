# Linux probe の guardian 異常終了回収設計

この文書は `tempest-linux-probe` の実装条件を固定するものです。
`2cda673` に基本の親専用回収を実装しましたが、全故障時点・M1 合格を意味しません。通常運転の lease/guard は `9e2fb47`、
起動失敗の追加 fixture は `68314b2` までの開発ブランチを前提とします。
実モデル・認証情報・本番 permit・VM/KVM の設定変更は対象に含めません。

## 所有権の条件

通常経路の `Group` と heartbeat lease は、異常回収のために再有効化しません。
ACK の identity を受信し、`Group::adopt` が保持 FD と dev/inode を照合した後に限り、
同じ directory FD を複製する回収専用型 `RecoveryGroup` を作成します。
この型は通常の attach/設定 API や Drop による回収を持ちません。
ACK 未受信の ROOT を固定 path から採用する経路は追加しません。

親の通常処理が終了し、通常 `Group` を disarm/drop した後に、次の条件を確認します。

1. serialization guard を引き続き保持している。
2. guardian の pidfd が死亡を示し、`waitpid` が terminal status を返して reap 済みである。
3. 専用 status pipe の bounded な読み取りで、正常な `released`/`recovered` 終端を先に識別する。
4. 親の ownership mode が通常所有中であり、R/D の送信後ではない。
5. heartbeat と通常 Group 操作を一方向に Forbidden にする。

この条件からだけ、watchdog module が回収専用の `DeadGuardian` proof を構築します。
proof は guard を借用し、回収完了前に serialization が解放されないことも表します。
pipe の EPIPE/HUP、guardian の SIGSTOP、単なる応答欠落からは proof を作りません。
`lease::clear` による通常 API の一括再許可も行いません。

上の送信後回収禁止条件は、次の拡張で置き換える予定です。現実装のcheckpointでは
R/Dの1 byte writeが成功してからmodeを変更し、未送信失敗時は親所有を保持します。
未送信時に限り最大5秒のPIDFD死亡待ちとreap後に専用回収を再試行します。
次の拡張ではCommandSentでもguardian死亡/reap確認後に部分回収し、正常terminal確認済みなら
mutationせず最終状態だけ検証します。生存guardianからの取戻しは認めません。
この拡張の状態機械と故障注入はまだ未実装です。

## 検知と対象の保持

lease の pulse ごとに guardian pidfd を poll し、heartbeat の rate limit 判定より先に死亡を検知します。
collector の poll 対象にも guardian pidfd を加えます。
既存の collector、barrier/report 待ち、wait/reap、hash/copy、長時間 lease 回帰試験の
pulse 箇所を列挙し、検知までの時間を fixture で測定します。
通常の poll 10 ms / sleep 25 ms と heartbeat 250 ms を基準にしますが、
host の停止・scheduler や同期 filesystem I/O の停止まで含む hard realtime の保証にはしません。

role と PIDFD/birth を持つ小さな registry を baseline より外側で保持します。
登録は Worker 完成後ではなく、clone 成功後の PIDFD 取得直後・group attach 前に行い、
attach 済み flag を後から一方向に更新します。PIDFD 取得前の失敗では、自分の fresh な
未 reap 子に対する既存の kill/wait 保証を維持します。
直接子と既知の descendant を区別し、直接子の通常 reap 成功時にだけその記録を除去します。
異常経路で Worker や baseline の local Vec が drop されても PIDFD を失いません。
registry はPID由来でない単調増加のRecordIdを発行し、directのattach/reap更新に使います。
既知のterminal waitpid成功時だけ該当IDを除去し、未知ID・二重更新・根拠のないECHILDを拒否します。

孫の生成から通常の PIDFD 取得までの窓もあるため、回収専用型は保持した role directory FD から
`cgroup.procs` を上限付きで snapshot し、未登録の生存 task の PIDFD も停止前に取得します。
PID/birth と既存の保持対象を照合し、PID の数値だけで再採用しません。
取得失敗時も自所有と証明済みの group の停止は行いますが、証拠不足を成功にはしません。

## 回収専用経路と記録

`RecoveryGroup::recover` だけが proof を受け取り、通常 Group API を経由せずに次を行います。

1. 保持 FD と ROOT の dev/inode を照合し、自所有 group に FD 相対で `cgroup.kill` を実行する。
   まだ attach していない直接子もあるため、registry の直接子には PIDFD による停止も行う。
2. 全保持 PIDFD の死亡と cgroup の `populated 0` を確認する。
3. registry の直接子だけを reap する。descendant に親であると仮定した wait を行わない。
4. 既知 role directory、ROOT、pin 済み RUN を照合して回収する。
5. guard 解放直前に最終不在を確認する。

親による回収記録は guardian の status と混同せず、別 schema の
`parent_recovery_status` に `guardian_dead → parent_owned → recovered/failed` を記録します。
死亡・reap・PIDFD・自所有回収・最終不在の全条件が揃った場合だけ `resources_removed=true` にします。
異常終了を通常 suite の成功や M1 合格に読み替えません。
各遷移に固定の件数を残し、失敗時も省略しません。reap未確認理由はechild/pidfd_alive/
evidence_missing/signal_failed/wait_failedで区別します。populated未確認はnullとして0と区別します。
回収前のfaultはfirst_faultとして保持します。

## 故障注入と残る範囲

barrier 前、payload 実行中、collector 中の guardian SIGKILL を分けて試験します。
barrier 前は clone 直後、PIDFD bind 後、attach 前/直後に分け、cgroup 外の子も残らないことを確認します。
guardian SIGSTOP だけでは親が所有権を取らない負例と、正常終端直後の race も独立に試験します。
各ケースは typed transition、検知時間、guardian reap、payload/descendant の PIDFD 死亡、
回収結果、次世代の起動または残留時の無変更拒否を確認します。

親による回収中に親も死亡する二重故障では、新たな guardian を自動生成しません。
結果が記録されず、payload/cgroup/RUN が残る可能性があります。
次の probe は既存 ROOT/RUN を採用せず拒否し、専用 VM 管理者が所有 identity と証拠を確認して回収します。
この二重故障、最上位 path の競合、全 bootstrap/timeout 順序、Drop cleanup の故障、
連続 output flood の公平性は独立した未完 gate として扱います。

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
4. 親のownership modeがParentOwned/CommandSent/TerminalAckのいずれかであり、死亡/reapが確認済みである。
5. heartbeat と通常 Group 操作を一方向に Forbidden にする。

この条件からだけ、watchdog module が回収専用の `DeadGuardian` proof を構築します。
proof は guard を借用し、回収完了前に serialization が解放されないことも表します。
pipe の EPIPE/HUP、guardian の SIGSTOP、単なる応答欠落からは proof を作りません。
`lease::clear` による通常 API の一括再許可も行いません。

R/Dの1 byte writeが成功してからCommandSentへ変更し、未送信失敗時は親所有を保持します。
未送信時に限り最大5秒のPIDFD死亡待ちとreap後に専用回収を再試行します。
CommandSentでもguardian死亡/reap確認後に部分回収し、正常terminal確認済みなら
mutationせず最終状態とregistryだけ検証してVerifiedを出します。生存guardianからの取戻しは認めません。
waitpidのterminal結果は一度だけ保存し、command側と回収側でreapを重複しません。
完全な正常terminalは別に保持し、後続partial/invalidがあってもmutationしません。
正常terminalは送信に成功したcommandと対応する完全な組合せだけを受理します。
Dはreason/triggerがともにexplicit_doneかつreleased、Rはともにrelinquishかつrecoveredで、
どちらもowner_dead=falseが必要です。送信前・対応しない組合せはinvalidとして記録します。
死亡後のdrainにも同じ検証を適用し、既知の正常terminalを後続invalidで上書きしません。
同一の正常terminalを重複受信した場合もInvalidとして記録し、最初の証明を保持します。
後続異常を根拠にmutationへ戻ることはなく、verify-onlyで残留を検出した場合はFailedとして保持します。
正常terminalがないfailed/partial/invalid/emptyは、不確実性を記録したまま死亡後の専用回収を行います。
これらの全順序のroot故障注入は未完です。

## 検知と対象の保持

lease の pulse ごとに guardian pidfd を poll し、heartbeat の rate limit 判定より先に死亡を検知します。
collector の poll 対象にも guardian pidfd を加えます。
既存の collector、barrier/report 待ち、wait/reap、hash/copy、長時間 lease 回帰試験の
pulse 箇所を列挙し、検知までの時間を fixture で測定します。
通常の poll 10 ms / sleep 25 ms と heartbeat 250 ms を基準にしますが、
host の停止・scheduler や同期 filesystem I/O の停止まで含む hard realtime の保証にはしません。

| 経路 | guardian確認箇所 | 通常の巡回間隔・制約 |
| --- | --- | --- |
| ready/Entered/Done・collector | eventのpoll前後・capture sweep後 | 最大10 msのpollにPIDFDを含む |
| 通常reap・全対象死亡待ち・memory OOM待ち | 各loopのpulse | sleep 5 ms |
| 通常Group操作・cleanup空待ち | verify/empty経由のpulse | 空待ちsleep 10 ms、filesystem操作時間は別 |
| code/library copy・hash・materialize | 各64 KiB巡回のpulse | 同期I/Oの停止は上限外 |
| 長時間lease回帰 | 各loopのpulse | sleep 25 ms |
| baseline終了・最終RUN回収 | cleanup開始直前のpulse | syscall実行時間は別 |
| spawn失敗時のfresh child kill/wait | 通常lease検知とは独立して自分の子を回収 | 最大3秒、専用の検知遅延検証は未完 |

最初の加入直後・孫実行中・collectorの3実測で得た6.531/0.607/0.764 msは、
親再開から最初のparent statusまでの保守的な上限です。全経路の最大値を証明するものではありません。
guardian自身のreceive/waitと、死亡reap後の回収専用loopは通常lease検知の測定対象から除きます。

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
collectorが返したfaultは、期待したlifecycle異常の検証結果へ変換する前にfirst_faultへ先着保存します。
その後のidentity検証・guardian死亡・cleanupの早期returnでも元の理由を上書きせず、
当該baselineの検証とcleanupが全成功した場合だけ消去します。
期待した負例のfaultは、呼び出し側が対応するscenarioと結果を受理した後に消去します。
未送信EAGAINでguardianが生存し、親がheartbeatを禁止したまま待機する場合は、
5秒lease失効によりguardianが親を停止して回収する可能性があります。
この順序では親の最終reportが出ないため、guardian statusを外部で保持する故障注入が必要です（未完）。

## 故障注入と残る範囲

barrier 前、payload 実行中、collector 中の guardian SIGKILL を分けて試験します。
barrier 前は clone 直後、PIDFD bind 後、attach 前/直後に分け、cgroup 外の子も残らないことを確認します。
guardian SIGSTOP だけでは親が所有権を取らない負例と、正常終端直後の race も独立に試験します。
各ケースは typed transition、検知時間、guardian reap、payload/descendant の PIDFD 死亡、
回収結果、次世代の起動または残留時の無変更拒否を確認します。

`80f78b3`のdiagnostic再実行では加入直後・孫実行中・collector待ち・SIGSTOP負例の4ケースと、
最後の次世代137観測を通過しました。初回のSIGSTOPケースはselect_targetで失敗し、根因は未確定です。
現在のfixtureはSIGSTOP負例を早い加入直後へ移し、既に加入したdummy roleもPIDFDで停止して
正常完了による対象消失を防ぎます。guardian生存・親の無出力・対象生存・ROOT identity保持を
500 ms確認した後にguardianをSIGKILLし、専用回収へ進むかを別に確認します。
この変更とterminalの組合せ検証を含む`efa9159`では、workspace224 testsと
4ケース・次世代137観測を再通過しました（driver exit=0、138.824秒）。
加入直後・孫・collector・SIGSTOP後の検知上限は6.729/0.805/1.335/0.376 msです。
SIGSTOP中の500 msは死亡検知の測定に含めず、その後のSIGKILLから測定しています。
guardianを停止したまま5秒以上の待機を重ねる経路のreport順序は別の未完試験です。

`python3 integration/linux_primary_fault_smoke.py` はx86_64専用VMで、自分の親の
`cgroup.kill` write入口をptraceし、固定ROOTのinode・対象FD・len=1・byte=`1`を照合します。
ReportEof確認後にguardianをSIGKILLするケースと、StdoutFlood確認後にそのwriteだけをEIOにするケースを分離します。
前者は専用回収の3直接子reap、後者は通常reaper後の空registryをVerifiedで確認します。
後者の監査件数0を新たな3子reapとは数えず、別に保持した3 roleのPIDFD死亡も確認します。
どちらも最終reasonとfirst_faultを別々にassertし、次世代が起動できることを検証します。
`a72df68`はworkspace226 testsと通常137観測を通過しましたが、同時故障fixture初回は
EOFケース完了後、EIOケースの次世代確認で失敗しました（driver exit=1、122.404秒）。
EIOケースもfirst_fault・最終reason・Verified・PIDFD死亡・資源不在までのassertは通過しています。
終了後ROOT/RUNは不存在ですが、次世代確認の失敗原因は未確定で、2ケース全体の成功とは扱いません。
追加診断では次世代の段階・終了コード・固定progress・path存在を元probeと分け、
許可した例外型とfixture内行番号だけを保存します。例外本文やtraceback本文は公開しません。

診断追加版`a51ed85`の再実行は、EOFケースのfixture内262行で
`resources_removed=true`の確認に失敗しました（exit=1、58.766秒、completed_cases=0）。
`first_fault=report_eof`のassertは通過していますが、ROOT/RUNが残留し、回収完了を主張できません。
終了後の読み取りでROOTと3 roleのcgroup.procsは空、すべてpopulated=0と確認しました。
残留ROOTはdev=28/inode=50290、RUNはdev=25/inode=6044で、削除・再採用せず証拠として保持しています。
詳細は実行環境の`/tmp/tempest-primary-fault-a51ed85{,-meta}.json`と
`/tmp/tempest-a51ed85-residual.json`に保存しました。元probeの詳細なparent statusは
失敗diagnosticに保存していないため、この記録だけで回収失敗の理由を断定できません。
2026-11-15のルーム投稿#16068で管理者から休止指示があり、この未解決状態で作業を区切ります。
投稿#16075の再開連絡後も、残留identityと全groupの空状態を読み取りで確認しました。
再開後のfixtureはassert前に完全なpublic auditを一意な
`/tmp/tempest-primary-fault-audit-*.json`へ0600で保存します。
raw stderrは保存しません。失敗した回収のcountsを含む保存内容と0600権限は、
実際のfixture保存ブロックを使った非root検証で確認しました。
失敗diagnosticの`audit_basename`でこのprivate fileへ対応付けます。
driverは固定prefix・8文字の一時名・`.json`だけを許可し、任意pathは公開しません。
`exited_after_listing`も固定理由として保持します。
rootでの再実行は未実施です。

その後、管理者の承認依頼#16107への承認決定#16117を専用toolで検証して、
指定identityをserialization guard下で再照合し、全group空・populated0・guardian不存在を確認しました。
ROOTの既知roleとROOTを除去し、元RUNは同一filesystemの
`/run/tempest-recovery-evidence-16107/original-run`へinodeを保持して移しました。
`/var/lib`へのrenameはEXDEVで無変更失敗したため、事前複製とは別に元inodeを保全しています。

`651fd36`の同時故障fixtureはexit=0、124.773秒、stderr=0で2ケースとも次世代加入まで通過しました。
最終ROOT/RUNは不存在です。binary SHA256は
`c8d8992b6408730fb2d5868204bb85ffc01d2c0fd63104314938e32a5ac4ce4a`です。
EOFケースはfirst_fault=report_eof、最終reason=watchdog_guardian_diedで、
guardian_dead→parent_owned→recovered、direct/dead_pidfds/reaped=3、未確認0、populated=falseでした。
EIOケースはfirst_fault=output_limit、最終reason=kernel/errno5で、
guardian_dead→verified、通常reaper後のregistry件数は0でした。外部保持した3 role PIDFDの死亡も両方で確認しています。
snapshot_stage/reason/errnoは両ケースともnullで、今回snapshot取得失敗は観測していません。
完全auditはroot私有の`/tmp/tempest-primary-fault-audit-i2qn09mu.json`（EOF）と
`/tmp/tempest-primary-fault-audit-9jluy4_l.json`（EIO）、実行結果は
`/tmp/tempest-primary-fault-651fd36{,-meta}.json`です。
前回の残留失敗と次世代確認失敗の原因は、この成功だけでは確定・解消扱いにしません。

### snapshot終了窓を固定する次のfixture案（未実装）

report_timeoutのcollectorで自分の親だけをptraceし、guardian単独poll入口
（x86_64 syscall=7、nfds=1、timeout=0、pollfdのFDのfdinfo/Pidが主guardianと一致）を捕捉します。
この入口でguardianをPIDFD SIGKILLし、死亡を確認してから親を再開します。
eventのpulse失敗とbaseline末尾のForbiddenにより、通常kill/fallbackより前にsnapshotへ進ませます。
そこでpidfd_open入口（434、引数がpin済みの生存role PID）を捕捉し、
先行する自所有cgroup.procs読取・guardian死亡を照合してからそのroleをPIDFD SIGKILLします。
外部PIDFD死亡を確認後に親を再開し、bind/exited_after_listing、Failed、空の同identity残留を期待します。
通常cgroup.kill入口でのEIOや成功値偽装は、どちらも後続leader fallbackがあり、生存対象を保証できません。
これらの初期案は採用しません。fixture自身が作った世代の後始末は、親terminal後にguardを再取得し、
pin済みidentity・全role空・populated0・全PIDFD死亡を再確認した範囲だけに限定する設計です。

追加の非root実験では、自分の直接子をPIDFD ledgerへ登録してから終了させると、
freshな`Process::bind`はIdentityで拒否する一方、保持済みPIDFDで死亡確認とreapが成功することを確認しました。
`registry::record_tests::pinned_dead_child_can_be_reaped_when_fresh_binding_is_rejected`がこの順序を固定します。
snapshotでの取得失敗は、回収済みregistryの証拠が欠けていることと必ずしも同義ではありません。
ただし前回実機がこの窓へ入った証拠はなく、snapshotの失敗を無視する変更は行っていません。
ルーム#16085の独立静的レビューでも、snapshot失敗を保存した後にkill/reap/populated0まで進み、
role削除前に失敗する経路が残留の形と一致すると確認されています。原因確定には次の実機auditが必要です。
次の診断ではcountsにsnapshot_stage（read_members/bind/membership/track）、
snapshot_reason（既存の固定fault理由）、snapshot_errno（kernel error時のみ）を残します。
最初のsnapshot失敗を保存し、registry回収時の件数初期化でも保持します。
失敗なしはnullです。bindのIdentityだけでは死亡とidentity不一致を区別できないため、
この記録を死亡の証明やsnapshot失敗を無視する根拠には使いません。
追加分類`exited_after_listing`はsnapshot専用bindでPIDFDが死亡を示した場合に記録します。
通常bindは従来のIdentityを維持します。所属確認ではbirth/cgroupの不一致を先に拒否し、
一致した対象のPIDFDが死亡を示した場合だけこの理由を返します。
この分類も死亡の観測であり、取得前の同一性やsnapshot網羅性を証明しません。
snapshot専用bindのstat読取、所属確認のstat/cgroup読取に失敗した場合も、
既に保持したPIDFDのPOLLINを再確認します。死亡観測時のみ同じ固定理由に分類し、
poll失敗や死亡未確認では元のerrorを保持します。通常bindの読取errorは変更しません。
非rootの自所有子テストで、生存中のENOENT保持・死亡後の分類・無効FDでの元error保持を確認します。
特にcgroup読取失敗後の`exited_after_listing`では所属の照合は未完です。
この理由から、そのtaskがROOTのmemberだったと推定しません。

親による回収中に親も死亡する二重故障では、新たな guardian を自動生成しません。
結果が記録されず、payload/cgroup/RUN が残る可能性があります。
次の probe は既存 ROOT/RUN を採用せず拒否し、専用 VM 管理者が所有 identity と証拠を確認して回収します。
この二重故障、最上位 path の競合、全 bootstrap/timeout 順序、Drop cleanup の故障、
連続 output flood の公平性は独立した未完 gate として扱います。

# Linux HOME・run state隔離gate

Issue #36の段階実装承認内で、Claude実体、credential、外部network、VMを使わずに
通常HOME相当の非到達と連続2 runの状態独立性を測る設計です。実ユーザーのHOMEや既存Claude設定は読みません。

## Fixture所有入力

root integration driverはserialization guard取得後に、固定のroot私有0700 directoryへ
synthetic HOMEを新規作成します。次の各分類を別directory/fileとして作り、値は固定dummy canaryだけにします。

- settings、hooks、plugins、MCP
- session、project state、cache
- lock、backup

driverとroot supervisorは保持dirfdから全entryのowner、mode、type、dev/inodeを確認し、各canaryを正読取します。
実HOMEのpath解決、列挙、metadata取得は行いません。synthetic HOMEのdirfdはclone前に固定FDへ複製し、
capsuleの`close_except`後にA/B/Gが`EBADF`を観測する負例にも使います。

## 1 runの証明

各roleのcapsuleは従来どおり独立mount/PID/network namespaceと新規tmpfs rootを作ります。
private HOMEとrun stateはそのtmpfs内に作り、role UIDだけがread/writeできます。

1. A/B/Gはsynthetic host HOMEの全分類pathが非到達で、継承canary FDも閉じていることを確認する。
2. 各roleは自分のprivate HOME canaryをreadし、run stateへ固定markerを`O_CREAT|O_EXCL`で書いてread backする。
3. workerはmarker作成後に固定phaseで停止する。親はworkerのPIDFDとmount namespace identityを照合し、
   `/proc/<pid>/root`の保持dirfdからmarkerを開いて内容、dev/inode、mount IDを記録する。
4. 親が続行を許可した後、同run照合用のroot/marker/namespace FDを閉じてから全roleを終了・reapし、
   cgroup空、role tmpfs/mount消滅、socket/path不在を確認する。保持FDをrun境界の外へ持ち越さない。

host側canaryの同時正読取、worker側のpath非到達とFD閉鎖、private HOMEの正到達を組にします。
従って、存在しない固定pathへの単発`ENOENT`だけを成功根拠にしません。

## 連続2 run

同じsynthetic host HOMEを保持したまま、run1を完全回収してからrun2を開始します。
親が発行するrun nonceとPID由来でない単調増加の世代RecordIdをrunへ結びます。PID、dev/inode、
namespace inode、mount IDの数値差はkernel再利用のため要求せず、数値の一致を同一世代の根拠にもしません。

- run1では`previous` markerがないことを確認してからrun1 markerを書き、親が生存中に保持FDで存在を証明する。
- run1終了後、全roleのPIDFD死亡/reap、cgroup空、socket/path/mount残留0を確認するまでrun2を開始しない。
- run2は新規tmpfsの作成成功を同runの保持FDから確認し、同じ論理pathでrun1 markerを読めないことを確認する。
  親が保存したrun1のnonce・世代RecordId・固定digestは、run1 markerが実在し検証済みだった証拠として残す。
- run2はrun2 nonceを含むmarkerを`O_CREAT|O_EXCL`で新規作成してread/write成功を確認し、
  run1と同じ完全回収条件を通す。

公開監査は固定check名、run番号、role、attempt/denial件数、namespace/mount identityの一致・不一致boolだけを出します。
canary本文、任意path、raw errno文字列、argv/envは出しません。失敗したrunを後続runの成功で上書きせず、
run1またはcleanupが不完全ならrun2を開始しません。

## 受入と非主張

### 段階実装の現在地（2026-11-16）

`706f289`の専用Linux実測では、両runのA/B/Gについてhost HOME非到達、private HOME正読取、
旧marker不在、marker作成・親観測と世代結合の固定checkがすべてtrueでした。
実行binary SHA256は`1b689f3a04632e50c714f3602bf02d499e613e2a60d53f989915f162f79aa873`です。
最終`resources_removed=true`、guardian終了・reapを確認しました。全体statusは`incomplete`であり、
`integration/linux_isolation_smoke.py`の全体`passed`条件は満たしていません。

`2e42c55`はrun境界のIPC socket明示閉鎖・EBADF確認とhost mountinfoのrole配下mount不在確認を追加しました。
`71ab7a4`は各run直前・直後のhost canary再読取とdev/inode・owner・mode・内容照合を追加しました。
`71ab7a4`固定binaryの実測は両run各21checkがすべてtrue、各runのhost正対照は18attemptでした。
binary SHA256は`3441032367564835393d05c5c7497c11ee7e147b142584aad2a7979a4ae29065`、
保存監査JSONのSHA256は`0be78f17771523e7d53049e63fd552d0d20d7dc6de0764751902821565400005`です。
socket閉鎖・host mount検査を含むcleanupを通過し、最終ROOT/RUNは不在、guardianはexit0・reap済み、
terminalは`normal_completion/verified`、経過時間は97177msでした。全体statusは`incomplete`です。
FD40はCLOEXECも閉鎖に寄与するため、
workerでのEBADFは継承非到達を支持しますが、`close_except`単独動作の証明とは扱いません。

現在のfixtureは各分類を固定fileで表現し、親保持dirfd経由で検証します。
同runの保持marker FDについて読取り前後のmount ID・inode・dev・length照合を追加し、以下の実測へ含めました。
`c5e26e0`で親が観測したmarker digestをnonce/RecordIdへ結合し、全roleの証拠を完了条件に追加しました。
その固定binary実測も両run各21check true、ROOT/RUN不在、guardian正常終了・reap済みでした。
binary SHA256は`7cf4e16d7ba3f58dcb0bff1e53bb6fed0b01f9f5a7fd20ac5f0beefc0314a0aa`、
監査JSON SHA256は`ac4acd658c3efe9fcabd060c1c6be0e0de99f6a1cfcdec374d4d02c5ecba5a2c`です。
独立driver `f469ad4`はcapture2/read18/各run21checkを実測し、driver exit0、probe incomplete、
elapsed110027ms、guardian回収、最終ROOT/RUN不在を確認しました。
private監査JSON SHA256は`f63d2ef3bc98cacfcb21b8de2afff16652a5796c1d3dc20b9152cb861d8a0736`です。
最終fixture `d598243`の独立実測もdriver exit0、wall112.81秒、capture2/read18/各run21checkを確認しました。
binary SHA256は上記`7cf4e16d…`と同じで、private監査JSON SHA256は
`9a282b775fa7110880ae0e77c9137f9c98fcc94a211aed2b4236f74ed1fd47f1`です。
probe elapsed108365ms、guardian normal_completion/verified・exit0・reap済み、最終ROOT/RUN不在です。
probe statusはincomplete、production_authorized=falseを維持します。
driver stderrは出力なしを観測しましたが専用byte counter未保存のため件数は未測定です。
追加root実測は行わず、このdummy checkpointを本番gateと分けて受入監査へ渡します。
上記の部分的実測を、この節全体のgate完了や本番実行許可とは扱いません。

### driver独立正対照の固定捕捉点（実装済み・最終受入継続）

専用root fixtureは自分がspawnしたsupervisorだけをptraceし、PIDFDと
`/proc/<pid>/stat`のparent/birthを開始前後に照合します。TRACEFORKは使いません。
捕捉点は既存`runtime::baseline`の`progress(scenario, "barrier")`にある
SYS_writeの正常終了直後です。次の`worker.start.send(b"G")`より前なので全roleはReady待機中です。
write入口でFDの保持object、固定RUN/progressのdev/inode・owner・modeを照合し、
上限128byteでpayloadを読み、state_run1/barrierまたはstate_run2/barrierだけを受理します。
write出口で戻り値がpayload全長と一致することを確認して初めて捕捉成立とします。

各捕捉で別processのfixtureがRUN/host-homeをNOFOLLOW保持dirfdで開き、
9固定fileをopenatして内容・type・uid0・mode0600・dev/inodeを確認します。
run2はrun1のdata-only identityと照合し、同じhost fixtureが実在し続けることを確認します。
driverはroot/host-home/file FDをrun内で閉じ、run間に保持するのはidentity値だけです。
捕捉順序はrun1→run2、各1回、合計2回/18読取を必須とし、重複・見逃し・誤FDは失敗です。

各停止区間は100ms以内を要求し、超過時は成功扱いせず直ちに再開・失敗回収へ進みます。
productionのlease/overall期限は変更せず、通常signalをtraceeへ転送します。
run2捕捉後はdetachして通常終了を待ちます。例外時は停止中traceeを確実に再開/detachし、
必要時には自所有supervisorをPIDFD kill/reapします。既存guardianの回収を有界待機し、
同世代ROOT/RUNのidentity確認なしの削除や新run開始を行いません。
driver正対照とprobe監査は別artifactとし、両者のbinary/run identityを結んで受入判定します。

rootless unitではmanifest/checkのexact schema、未知field拒否、run順序、identity比較を検証します。
専用Linux root integrationではhost正対照、全role負例、各role正対照、nonce/RecordIdによる世代結合、
新規tmpfsと`O_EXCL`生成、各run完全回収を実測します。

このgateはdummy capsuleのHOME・state分離だけを支持します。Claude Code 2.1.325の実際のsettings探索、
session保存停止、subscription credential、direct API通信、本番B/VM、KVM/imageの成立は証明しません。

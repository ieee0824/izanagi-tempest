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
これらを含む固定hashのLinux実測は進行中です。FD40はCLOEXECも閉鎖に寄与するため、
workerでのEBADFは継承非到達を支持しますが、`close_except`単独動作の証明とは扱いません。

現在のfixtureは各分類を固定fileで表現し、親保持dirfd経由で検証します。
設計上のdriver側独立正対照、同run内のmount ID再照合、run1 marker digest保持の実装・受入監査は残っています。
上記の部分的実測を、この節全体のgate完了や本番実行許可とは扱いません。

rootless unitではmanifest/checkのexact schema、未知field拒否、run順序、identity比較を検証します。
専用Linux root integrationではhost正対照、全role負例、各role正対照、nonce/RecordIdによる世代結合、
新規tmpfsと`O_EXCL`生成、各run完全回収を実測します。

このgateはdummy capsuleのHOME・state分離だけを支持します。Claude Code 2.1.325の実際のsettings探索、
session保存停止、subscription credential、direct API通信、本番B/VM、KVM/imageの成立は証明しません。

# 固定loopback隔離テスト案

room #16934 のレビュー用。既存の特権管理経路から専用の子cgroupを一つ作り、固定テストbinaryを引数なし、空の環境で一回起動する。親がloopback上に専用listenerを二つ確保し、片方のportをこの試行の許可先とする。両listenerを保持したまま実行し、port競合やattach状態の不一致では子を解放せず終了する。

既存GCCとLinux UAPIヘッダで、固定命令列と `bpf` syscall ABIをビルドする案を採る。固定アドレスと親が確保したportの比較のみとし、入力ファイルから任意命令や宛先を受け取る経路は設けない。親だけがプログラムとlink FDを保持し、対象cgroupの同一性と有効なattachを照合する。

子は接続前の待機点で専用cgroupへ収容する。不要なFDを閉じ、専用UIDへ移行してcapabilityを消去し、no_new_privsとseccompを適用する。親はPID、cgroup、FD、capability、seccompの事後状態を確認してから実行を許す。子にcgroupの書き込み経路やBPF管理FDを渡さない。

- 正例は許可listenerへのIPv4 TCP接続一回とし、親が受理を独立に数える。
- 負例はもう一つのloopback listenerへのTCP接続と、IPv6、UDP、raw、Unix socketの生成を拒否する。同じ試験で許可外listenerの受理数がゼロであることを親が集計する。拒否とlistener不在を区別するため、親側から両listenerの到達を先に確認する。
- 親は絶対期限を持ち、子を回収して専用cgroupが空になったことを確認してからlinkを閉じ、cgroupとlistenerを削除する。回収が確認できない場合は隔離を解除せず、失敗を記録する。

この試験の受入範囲は固定ホスト上のdummy listenerへの接続制御である。実IzanagiのVM同一性と設定ファイル閉包は後続試験で確認する。ここでは読取調査のみ実施し、load、attach、unit追加、VM起動はレビュー待ち。

## 既存ファイルのSHA-256

| ファイル | SHA-256 |
| --- | --- |
| /usr/bin/cc、/usr/bin/gcc | 1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26 |
| /usr/include/linux/bpf.h | 69f6566ab51435fc497fe38832d6429abbf9c4b3ee1b15ac34307e496dc7ee4d |
| /usr/include/linux/filter.h | aeb1560f02eff26dfea4ad4596d77c05d2bad3eab87cf3dd5aaf6b64ad2f5053 |
| /usr/lib/x86_64-linux-gnu/libbpf.so.1 | 0e9998e17e38d78e5ce953f89a5e6a7c8b457d3e1bfe71e3ec5a1cfb05bbd1c3 |

libbpfのruntime共有ライブラリはあるが、標準include位置に開発ヘッダがなく、PATH上にclang/llcはない。bpftoolの実体は既存metadataに記録済み。

## 管理プロセス異常終了時の回収

link FDをcontrollerだけが持つ構成では、異常終了でworkerの終了より先にポリシーが消える。専用cgroupへのlinkをrootだけが触れる既存bpffs配下に試行専用名でpinし、controllerと独立した回収処理に引き継ぐ案とする。利用可能なbpffs、既存管理経路による回収、試行台帳とpinによる照合が確認できなければworkerを解放しない。専用の永続mountを追加する前提にはしない。

1. 試行IDとcgroupのdev/inodeを捕捉し、管理側で回収対象として登録する。attachとpinの途中で異常終了しても、workerはまだ接続試行を開始していない。
2. pinのlink IDとattach対象を照合してから、権限を落としたworkerを解放する。workerはlink FD、bpffsの操作権限、別cgroupへの書き込み権限を持たない。
3. 正常時も異常時も、管理側は同じcgroupを照合してから残存workerを終了させ、pidfdの終了確認とcgroupの `populated 0` を確認する。その後でのみpinを解除する。回収結果が不明ならpinを保持し、再実行で上書きしない。

接続前、worker試行中、worker回収後の対照を別区間として記録する。各区間では親が両listenerのaccept増分を独立集計する。worker区間の合格条件は許可側1、許可外側0、および許可外TCP接続で期待する拒否errnoの一致。前後対照は両listenerに各1件を要求し、各区間の遅延接続を次区間の成功に数えない。

controllerは子を待機点へ置いてから起動許可用のleaseを取得する。lease取得後はforkしない。既存の管理経路がlease取得済みの状態からforkする場合は、子分岐の最初にコピーを閉じる。CLOEXECだけではforkでコピーされるFDを防げないため、試験ではcontroller正常終了後と強制終了後の両方で、独立管理側によるlease再取得を確認する。

## pidfd回収の再現

リポジトリrootから次を実行する。BPFのロードやcgroup変更には入らず、実子の生存中、pin状態不明、解除後の終了済みを検査する。

```sh
test_dir=$(mktemp -d)
gcc -std=c17 -Wall -Wextra -Werror docs/evidence/connect4-fixture-001/recovery_test.c -o "$test_dir/recovery-test"
timeout 5s "$test_dir/recovery-test"
```

固定hostで終了0、出力は `live=EBUSY unknown=ESTALE exited=reaped`。

## 監督プロセスと試験制御の分離

監督をworkerの直接の親にする。監督が元のpidfd、cgroup FD、元link FD、台帳と許可パイプの書き込み端を保持する。試験制御側には結果取得と試験開始要求のための専用パイプだけを渡す。配置、準備完了の確認、許可トークンの送信、`waitid(P_PIDFD)`とreap、cgroupとlinkの回収はすべて監督が行う。試験制御側へpidfdを渡してwait/reapを委譲する構成は採らない。

監督は試験制御側の終了、要求パイプのEOF、期限切れを回収の契機とする。子を生成したら許可前の失敗でも元pidfdで停止を確認する。固定済みlinkは子が終了しcgroupが空になるまで維持する。試験制御側を強制終了する試験では、起動許可前と許可後の両方で、監督が子を回収し、linkとcgroupを回収して台帳を退役させたことを確認する。監督自体の強制終了からの回収は別の障害条件であり、試験制御側の強制終了試験の成功に含めない。

## 固定ホストでの試験前後の確認

`fixture.c` は引数なしで固定名の専用cgroup、台帳、pinを使う。実行に先立ち、同名のcgroup・pin・稼働中台帳・退役済み台帳がいずれも存在しないことを管理側で確認する。既存パスが見つかった場合は、その試行への帰属を確認するまで保持する。ビルドと非特権回帰は試験入口を起動せずに実施できる。

```sh
test_dir=$(mktemp -d)
gcc -std=c17 -Wall -Wextra -Werror -fanalyzer docs/evidence/connect4-fixture-001/fixture.c -o "$test_dir/fixture"
gcc -std=c17 -Wall -Wextra -Werror docs/evidence/connect4-fixture-001/recovery_test.c -o "$test_dir/recovery-test"
timeout 5s "$test_dir/recovery-test"
```

非特権回帰では `controller_killed=ECANCELED` と `live=EBUSY unknown=ESTALE exited=reaped` を得た。正常な実機試験の受入には、前・中・後の受理件数が順に `(1,1)`、`(1,0)`、`(1,1)` であること、workerの正常終了、固定pinと専用cgroupの不在、元台帳の不在と退役済み台帳の存在を個別に確認する。起動許可の前後で制御側を停止する負例には、停止を各段階へ同期させるテスト用の入口が別途必要である。

## 固定ホストの正常系試行 001

room #16989 の範囲で、`b98090c` の `fixture.c` と `policy.c` を `git show` で別ディレクトリへ取り出してビルドし、引数なしで `sudo -n` から一度実行した。バイナリのSHA-256は `6609070fdaf3e4ddc13c40a592ec89e0b355e2e1d7d79573cb23f9916e3a29a1`。起動前に固定名のcgroup、pin、現行台帳、退役台帳の不在を確認した。

終了コードは1。前対照の受理件数は許可側1件、拒否側1件。試験本体は `Operation not permitted` で終了し、workerの接続結果と後対照の受理件数は未観測。ログは拒否された操作を特定できる粒度を持たないため、正常系の受入は未達である。

終了後に `/sys/fs/cgroup/tempest-connect4-fixture-001`、`/sys/fs/bpf/tempest-connect4-fixture-001`、`/var/lib/tempest-connect4-fixture-001` の不在と、`/var/lib/tempest-connect4-fixture-001.retired` がroot所有・0700のディレクトリであることを確認した。固定名での再実行は行わず、退役台帳を保全する。結果は room #16990 に投稿した。

## 診断試行と修正後の正常試行

`5e4a7ed` を `-DCONNECT4_CASE=3` でビルドし、診断専用名 `tempest-connect4-fixture-diagnostic-001` の4パスが未使用と確認して一度実行した。バイナリSHA-256は `122f132ca834dc3f7f566dcbc3bf634bd1a86ea8a2fb55871c8200e1f2692794`。終了1、前対照 `(1,1)`、試験中と後対照は未観測。診断は `worker-privileges` の `Groups` 不一致で `errno=1`、`pin_created=1`。終了後に固定pin、専用cgroup、現行台帳の不在と退役台帳の存在を確認した。room #16995 に報告済み。

同ホストで補助グループが空の別プロセスを観測すると、`getgroups()` は空で、`Groups:` の後ろにタブと空白があった。`4c53105` で空白だけの値を空集合として扱い、補助GIDや打切りは拒否するよう修正した。

`a1b3180` を `-DCONNECT4_CASE=4` でビルドし、固定名 `tempest-connect4-fixture-normal-002` の4パスが未使用と確認して一度実行した。バイナリSHA-256は `a5f1f08d62cab54486d2b74b3cd6b600614b1433410ec68eb8e2d0d43e74a3b9`。終了0、前 `(1,1)`、試験中 `(1,0)`、後 `(1,1)`。workerは `CLD_EXITED`、status 0。workerのstatus 0は許可先への接続成功と拒否先への `EPERM` の両方を要する。終了後に固定pin、専用cgroup、現行台帳の不在とroot所有・0700の退役台帳を確認した。元2件の台帳の `trial-identity` SHA-256は一致した。room #16997 に報告済み。起動許可前後の強制終了は未実行。

## 起動許可前後の制御側強制終了試験

room #16998 の範囲で、固定ホストにて `63b0442` を `-DCONNECT4_CASE=1` または `-DCONNECT4_CASE=2` でビルドし、各固定名のcgroup、pin、現行台帳、退役台帳が未使用であることを確認した。既存の管理経路 `sudo -n` から各一回実行した。

| 同期点 | 固定名 | バイナリのSHA-256 | 観測 |
| --- | --- | --- | --- |
| 起動許可直前 | `tempest-connect4-fixture-before-001` | `cfc426b72abe9be778860eb58ef719d9d2d97d3da932a4a45f5cefd51c8a20b8` | 制御側終了を観測。許可段階でerrno 125、pin作成済み、退役台帳にrelease-intentなし。 |
| 起動許可受信直後 | `tempest-connect4-fixture-after-001` | `111fff8b0df3898e95a4c27f7e42e741c72fc6195d229ef33fd0b43f617b5a78` | workerの許可受信を確認。制御側終了を観測した時点でworkerは生存。退役台帳にrelease-intentあり。 |

両ケースで想定どおり `ECANCELED`、終了1。ログで監督が元pidfdを使ってworkerの終了を確認し、reapしたことを確認した。前対照はいずれも `(1,1)`。試験中と後対照のaccept数は未観測。事後は各固定名のpin、cgroup、現行台帳が不在で、退役台帳はroot所有・0700だった。結果はroom #16999に報告した。監督自身の強制終了は試験対象外。

## 監督が終了した場合の上位回収

room #17000 の設計案。最上位の回収プロセスは、監督を生成する前に `PR_SET_CHILD_SUBREAPER` を設定し、生成した監督のpidfdを保持する。試行用ディレクトリとcgroup、元link、試行台帳は上位側が確保して保持する。監督がworkerを生成したら、接続許可を送る前に専用のUnixソケットでworkerの元pidfdを上位へ渡す。このソケットは管理プロセスだけが保持し、workerには継承させない。

上位側は想定した試行ID、cgroupのdev/inode、元linkとprogramのID、worker PIDと受領したpidfdを照合し、必要なFDをすべて保管できた場合にだけ承認を返す。承認の欠落、余分なFD、受信エラーでは起動ゲートを開かない。監督は通常時の直接の親としてwait/reapを担当する。

監督の元pidfdで終了を観測してから、上位側が同じ排他ロックを取得する。監督による通常reapが確認できていない場合は、上位側で `waitid(P_PIDFD, ..., WEXITED | WNOHANG | WNOWAIT)` が成功することを確認して、workerをwait可能な子として引き取る。元pidfdで停止して終了・reapを確認し、対象cgroupが空になり、固定リンクが元の試行情報と一致した場合にのみpinを解除する。所有や同一性を確認できなければpinと台帳を保持する。

固定の失敗試験では上位側が受領確認を返した後に監督を止める。まず許可前の停止と、workerが許可を読んだ直後の停止をそれぞれ同期させる。監督終了、workerの再親化と元pidfdによる回収、pin/cgroupの不在、試行台帳の退役を別々に記録する。上位回収プロセスも失われる場合は別の障害条件として扱う。

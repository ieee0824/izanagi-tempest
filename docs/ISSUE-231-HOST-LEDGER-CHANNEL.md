# VM 外台帳への専用照会経路

対象は #231。ホストの永続台帳と署名鍵から、ゲストの管理者プロセスへ
最新の許可状態を渡す。実装と VM 間検証は進行中。

## 配備と対象の結び付け

専用 CID を起動時の QEMU 構成へ指定する。root 所有の登録には target_id、
毎回生成する boot_id、CID、QEMU の PID と /proc/PID/stat の開始時刻、
QMP socket の参照を記録する。ブローカーは受信した実 peer CID を登録と照合し、
QEMU の同一プロセスが running であることを確認する。要求本文の CID は使わない。
旧 boot_id と別 CID の要求は拒否する。登録更新時は旧接続を閉じる。

既存 tempest-login-test は PCIe root port がなく、稼働中の追加は QEMU に
拒否された。再起動前に owner の SSH セッション終了、ディスク同期、
現起動構成と鍵・転送先の保全、専用 CID を加えた起動コマンドを確認する。
同じディスクと SSH hostfwd で復帰し、既知のホスト鍵・hostname・台帳世代を照合する。
検証には専用チャネルを初期構成に含む別の使い捨て VM を使用する。

## 要求と応答

改行区切り JSON、要求は最大 1024 バイト、応答は最大 4096 バイト。
要求は version、operation、target_id、boot_id、permit_id、generation、
challenge を持つ。challenge は毎回新しい32バイト乱数の小文字16進表現。
operation は照会と消費を区別する。消費の応答喪失後も、既存の VM 外台帳の
消費済み状態を維持する。同じ許可の消費再実行は拒否し、再照会で状態を取得する。

署名対象に要求全体と最新の commit、失効版、発行時刻、有効期限を含める。
既存の host-permit-receipt 用途とは署名ドメインを分ける。
ゲストは公開鍵、要求との一致、対象・起動世代・許可・台帳世代、期限を照合する。

接続上限は VM ごとに1、全体8。各要求は接続開始から2秒以内に完了する。
受信途中で期限を延長しない。失効監視は最大1秒間隔、応答の有効期間は最大2秒。
読取りはホストの既存共有ロック、消費は排他ロックで行い、公開と独立確定点の
不一致や未完了状態を拒否する。

## supervisor の変更

管理者 PTY は本人操作に使用する。照会用 transport は独立した FD とする。
preflight_for_supervision と lock_current のローカル台帳読取りを専用照会へ移す。
応答期限超過、署名不正、切断、失効、対象不一致で子・通信経路を回収する。
開始ゲートと失効監視の両方を同じ照合処理へ接続する。

## VM 間の検証

正常照会、消費と再消費拒否、応答喪失後の再照会、要求途中の切断、期限切れ、
別 VM、旧 boot_id、誤対象、署名不正、失効直後、過大要求、同時接続上限を確認する。
ホスト台帳の永続状態とゲストの回収結果を独立に記録する。

## 停止時間の計算

失効直後に前回照会が完了した場合、次回照会開始まで最大1秒、照会期限が2秒なので、
照会失敗の検出は最大3秒となる。署名済み状態の残存有効期限が先に尽きる場合は
その期限で停止する。再接続はこの期限を延長しない。停止要求から回収完了までを R 秒とし、
回収完了の上限は `min(3秒, 状態の残存有効期間) + R` とする。
ゲスト統合時に回収処理のタイムアウトを含めて R を確定し、実測と期限の試験を追加する。
現段階では回収完了時間の保証は未検証。

通信処理の回帰試験は次で実行する。

```sh
python3 -m unittest discover -s tests -p test_host_ledger_channel.py -v
```

## 専用チャネルの起動確認

root 権限、QEMU、静的リンク用 C ツールチェーン、cpio、zstd、BusyBox、
指定カーネル版の vsock モジュールを使用する。

```sh
sudo python3 integration/qemu_vsock_probe.py \
  --kernel /boot/vmlinuz-6.8.0-149-generic \
  --kernel-release 6.8.0-149-generic
```

ディスク・NIC のない最小ゲストを CID 232 で起動し、ホストがソケットから取得した
実 CID と要求を照合する。ゲストの応答確認と電源断まで確認する。
この試験は専用通信路の疎通を検証する。署名台帳、supervisor、失効時の回収を
通す VM 間試験は別途追加する。

Rust 診断入口を使用する署名応答の VM 間試験は次で実行する。

```sh
cargo build --locked -p tempest-linux-probe --bin tempest-host-channel-verify
sudo python3 integration/qemu_vsock_probe.py \
  --kernel /boot/vmlinuz-6.8.0-149-generic \
  --kernel-release 6.8.0-149-generic \
  --native-verifier target/debug/tempest-host-channel-verify
```

現在このモードはホストが固定ダミーの commit を署名し、ゲストの Rust 診断入口が
公開鍵・要求・期限・独立に指定した台帳 ID を検証する。`--managed-ledger` では実 SQLite と QMP 管理登録へ接続し、
`--supervisor-test` では実 supervisor も使用する。

## ゲスト supervisor の設定

`/etc/tempest/host-channel.json` を root 所有・0600 の単一リンク通常ファイルで配置する。
設定には target_id、permit_id、generation、boot_id、ledger_id、minimum_sequence を記録する。
独立に照合した32バイト公開鍵は同条件の `/etc/tempest/host-channel-key` に配置する。
対象・許可・世代は公開ログイン設定と一致させる。設定が存在する場合、形式や対象が
不一致なら拒否する。

開始前の preflight は issued または consumed の台帳を読み取り照合する。
開始時の verify_for_supervision はホストで consume し、その署名応答から期限を取得する。
開始ゲートと FixtureStop の lock_current は新challengeで照会する。
再照会の期限は保持中の単調時計期限と2秒後の早い方で、受理した sequence を下限に更新する。
実 supervisor の試験範囲と残課題は末尾に記録する。

## 時計差に対する fresh 応答の期限

最小ゲストで issued=1795337708348、guest now=1795337707869、
expires=1795337710348 を観測し、約479 ms の時計差で壁時計検証が拒否した。
新しい要求では challenge 生成前の Instant を保存する。ホストは最新台帳を照合し、
expires を発行時刻+2000 ms と管理登録の失効時刻の早い方に制限する。
ゲストは要求全体への署名と0より大きく2000 ms以下の寿命を照合し、
要求開始Instant + (expires-issued) を期限とする。要求開始は発行より前なので、
通信時間とホスト処理時間も寿命から差し引く。受信時を起点にしない。
壁時計による offline 診断は別の検証経路として保持する。

再照会は旧 lease の期限内に受信・検証を終える。成功後は新しい要求開始時刻に
新署名の寿命を加えた期限へ更新する。旧期限で新 lease を恒久的に制限しない。
既存の overall 許可期限は supervisor 側で継続して制限する。
同期前の fresh 経路はホストの絶対時刻をゲストの壁時計と比較せず、署名寿命、
要求一致、ホスト側残存期限 cap を照合する。この設計は cc-sakura #18163 の確認による。

## 独立した承認期限

ホスト管理者は原本の通信終了・単回許可終了・公開世代終了の UTC 時刻を
`host-login-authority/channel-approval.json` にミリ秒単位で登録する。
対象の target_id、permit_id、generation、boot_id と、
communication_expires_unix_ms、permit_expires_unix_ms、generation_expires_unix_ms を記録する。
root 所有・0600 の単一リンク通常ファイルとし、登録 expires_unix_ms を
これらの最小値以下へ設定する。ブローカーは各要求で独立承認を再読取りし、
対象不一致と期限超過設定を拒否する。

## 実 supervisor の失効試験

```sh
cargo test --locked -p tempest-linux-probe --lib --no-run
sudo python3 integration/qemu_vsock_probe.py \
  --kernel /boot/vmlinuz-6.8.0-149-generic \
  --kernel-release 6.8.0-149-generic \
  --native-verifier /absolute/path/to/the/libtest/executable \
  --managed-ledger --supervisor-test
```

ゲストの ignored 試験を単一スレッドの子で実行し、preflight、consume、query を
実 SQLite と QMP 登録を経由して処理する。ダミー子は独立した PID/network namespace
で sleep と TCP 待受けを起動する。IPv4/IPv6 両方の表で待受けと子の生存を確認し、
正常な query を3回以上受理してから停止を注入する。

`--stop-mode revoke|disconnect|silence|renew|late-receipt` を指定できる。renew は6回の更新に
各400 msの遅延を入れ、初回2秒 lease を超えて正常更新できることを確認してから revoke する。
各ケースは AdministratorStop、namespace_reaped、記録した全子 PID の消滅、
保持した network namespace 内の待受け消滅を確認する。fork 子の panic は専用 hook で
exit 101 とし、親が非0終了を検出する。意図的 panic の対照試験も用意する。

無応答ケースのホスト側 fault_to_vm_exit_seconds は、ホストが意図的に2.5秒待つ時間を
含む上限値であり、正確なゲストの停止遅延ではない。ゲストは elapsed_ms と
accepted_queries を別に記録する。TLS ゲートウェイそのものの回収、別 VM/旧 boot の実 VM 拒否は引き続き未完了。

`late-receipt` は最後の正常応答を600 ms遅延させ、旧 lease の残存期間を減らす。
次の問い合わせには、生存中の実 QEMU と台帳を確認して正しく署名した応答を生成し、
1600 ms 保持する。署名応答自体の期限がまだ有効であることをホストで照合してから
送信する。ゲストは旧 lease の期限で停止し、正常受理回数が厳密に3回であることを
確認する。実測ではゲスト全体2077 ms、正常3回、子 PID/ソケット回収を確認した。
この試験は旧 lease をまたぐ受信を扱い、検証処理そのものの途中で期限を超える
ケースは別途必要である。

## 実トランスポートと識別情報の不一致

`--stop-mode wrong-cid|old-boot|old-process|wrong-device-cid` は、実 CID 232 の
VM と3回正常に照会した後、次の不一致を注入する。

- wrong-cid: ホスト登録を CID 233 とし、実 vsock 接続元との不一致を拒否する。
- old-boot: ホスト登録と独立承認を boot2 とし、ゲストが保持する boot1 を拒否する。
- old-process: 登録した QEMU start ticks を変更し、実プロセス寿命との不一致を拒否する。
- wrong-device-cid: 生存中の実 QEMU に QMP で問い合わせ、登録 CID 233 と実デバイス
  CID 232 の不一致を独立に確認する。その後は接続を閉じてゲストの回収を確認する。

いずれも専用の拒否理由を照合し、ゲストの正常受理が厳密に3回であること、
AdministratorStop、子 PID と待受けの消滅を確認した。ゲスト全体は順に
116/117/121/117 ms。これは登録情報の不一致注入であり、別 VM 同時起動、実際の
VM 再起動、停止した旧 QEMU の情報を再利用する試験の代わりにはならない。

## 呼び出し元の短期期限

同じコマンドに `--caller-deadline-test` を加えると、ゲストの Client が正常な
preflight を一度完了した後、100 ms の呼び出し期限で再照会する。ホストは実台帳と
QMP を検証して署名応答を生成するが、300 ms 保持する。ゲストはエラーを返し、
minimum_sequence を更新しないこと、250 ms 未満で返ることを確認する。
初期実測は99 ms。最初の試験は起動直後の初期化時間が測定に入り、問い合わせ送信前に
期限を超えたため、正常照会を先に行う対照へ修正した。この試験は起動直後の
エントロピー取得やスケジューリング遅延を含む実時間上限を保証するものではない。

実 QEMU が終了し、ホストの wait で回収された後、同じ登録を
require_live_instance と serve_query の両方へ再投入する検証も行う。
どちらも pidfd_open の ESRCH で拒否し、署名呼び出しが0回、応答が空であることを
確認する。既存登録の値を人工的に変えるだけでなく、終了済みの実プロセスに対する
確認である。PID 再利用、同じ CID の新 VM への登録持ち越しはまだ別の試験が必要。

`--managed-ledger --peer-lifecycle-test` は supervisor-test を付けず、native verifier
バイナリを指定する。独立した QEMU を CID 232 と233で同時起動し、両方の実 vsock
接続を受ける。CID233 の実要求を CID232 の登録で serve_query に渡すと、
peer mismatch、署名0回、空応答となる。各 VM は別々の PID/start ticks/QMP socket
を持ち、両方が running であることと実デバイス CID を確認する。それぞれ自身の
登録では署名応答を受けて native verifier が成功し、正常終了する。

試験は実ソケットから取得したフレームと peer CID を保持し、拒否確認と正しい登録での
確認を行うため、ハンドラへの再投入に socketpair を用いる。broker の accept 経路と
接続枯渇制御の試験は別である。同じ CID の再起動持ち越しと PID 再利用も未完了。

`--managed-ledger --restart-lifecycle-test` は、最初の実 QEMU の正常終了・回収と
旧登録の ESRCH 拒否を確認した後、公開 request の boot_id を boot2 に変更して
同じ CID 232 の新しい QEMU を起動する。新 VM の実要求を旧登録で処理すると
identity mismatch、署名0回、空応答になる。新しい PID/start ticks/QMP socket と
boot2 を登録し、独立承認も更新すると、同じ台帳を使った署名応答を新 VM の native
verifier が検証して正常終了することを確認した。

これはゲスト OS 内の reboot コマンドではなく、QEMU プロセスを終了して新規起動する
ライフサイクル境界の試験である。boot_id はホストが登録する公開世代識別子を使う。
カーネルの boot UUID 自動取得や PID 再利用を強制する試験は含まない。

## 実ブローカーの同一 VM 接続上限と回復

`--managed-ledger --broker-limit-test` は実 AF_VSOCK listener を fork した
broker.serve に渡す。VM の初回正常応答の後、ゲスト C probe が未完了の `{` 要求を
保持する。150 ms の間その接続が開いていることを確認し、同じ実 CID から2本目を
接続すると500 ms以内に EOF/reset で拒否される。最初の未完了要求も2.5秒以内に
EOF/reset となる。その後、ゲスト native verifier が正常な応答を取得する。
初回・回復後の両方の署名検証成功と probe の成功記録を照合する。

この試験は実 broker の accept、同一 CID の並行要求拒否、要求 timeout、slot の
回復を扱う。異なる CID で全8slotを埋める試験や、終了中の接続の公平性までは含まない。

## TLS ハーネス用 userspace の準備（接続作業中）

`integration/prepare_login_vm_runtime.py` は private mount namespace 内に、
既存 TLS ハーネスが必要とするツール、Python 標準ライブラリ、暗号ライブラリ、
固定 CLI/bundle、試験バイナリ、integration スクリプトだけを bind mount した
ディレクトリを作る。QEMU の9pエクスポートは必ず読み取り専用にし、このスクリプトの
`--command` 内から起動する。ホスト全体や認証ディレクトリは公開しない。

```sh
sudo unshare -m --propagation private python3 integration/prepare_login_vm_runtime.py \
  --output /var/lib/tempest-login-runtime-test \
  --binary-directory /absolute/path/to/target/debug \
  --libtest /absolute/path/to/the/libtest/executable \
  --command chroot /var/lib/tempest-login-runtime-test /usr/bin/python3 \
  -c 'import ssl, sqlite3, pty; print("LOGIN_VM_PYTHON_RUNTIME_OK")'
```

処理後は bind mount を逆順で解除し、一時ディレクトリを削除する。固定実体を
コピーまたは hardlink せず、nlink=1 の検証条件を維持する。ホストの chroot で
SSL/SQLite/PTY、cryptography の Ed25519 生成、OpenSSL 起動を確認済み。
最初の試験で不足していた OpenSSL provider ディレクトリも追加した。
実 VM の9pマウントと TLS ハーネス実行、ホスト側台帳への callback 分離は未完了。

実 VM で userspace を確認する場合、上記 --command 以降を次に置き換える。

```sh
--command python3 integration/qemu_login_runtime.py \
  --runtime /var/lib/tempest-login-runtime-test \
  --kernel /boot/vmlinuz-6.8.0-149-generic --kernel-release 6.8.0-149-generic
```

起動側は NIC を付けず、vsock と readonly=on の9pエクスポートだけを追加する。
ゲストも9pを ro でマウントする。既存ファイルの変更と新規作成が EROFS で
拒否されることを確認した。ゲスト内で SSL/SQLite/PTY/Ed25519、OpenSSL、
loopback と nft table の作成・削除も成功した。さらに既存の pin_artifacts を使い、
固定 CLI/bundle、TLS fixture の OpenSSL/libssl/libcrypto、BusyBox の uid/mode/
nlink/size/digest 検証が成功した（ignored試験1件、約22秒）。
これは userspace と固定実体の準備確認であり、TLS/FixtureStop remote 回収自体の
完了を示さない。VM終了後は起動プロセスを回収してから全bind mountを解除する。

## 既存 TLS baseline の実 VM 検証

上記 qemu_login_runtime.py に `--tls-fixture` を追加し、release の試験バイナリと
libtest を渡す。既存 combined_login_diagnostic の local 台帳経路を実 VM で実行し、
revoked / missing / disconnect / expired / authority-pending の全5ケースで、
固定子の TLS・証明書・誤名拒否・直接接続拒否、子と gateway の回収、同じ許可と
作業/設定世代の回収を確認した。起動前の拒否4件も成功した。ゲスト全体約84秒。

準備時の修正は、専用 bundle の隔離領域へのコピー、入れ子の元実体 mount を
保存する rbind と再帰解除、libtest の quiet 出力、固定 /usr/sbin/ip の別名、
/dev/stdin 等の標準 fd リンク。期限切れ対照は署名期限まで待つよう修正した。
また Host を監視する TLS fixture の固定8秒上限が署名期限より先に切れてしまう
不整合を直し、期限+1秒の回収猶予まで watcher を維持する。認可停止は引き続き
FixtureStop が署名期限で行い、認可期間を延長しない。

これは local baseline の完了であり、外部ホスト台帳から vsock を通した
remote callback と TLS 回収の組合せは次の段階である。

### 認可期限と回収猶予の分離

上記 fixture の期限変更を再点検し、accept/要求読取り/open_tunnel/relay に
expires+1秒が渡らないよう修正した。Host は expires を認可期限とし、watcher の
終了確認だけ expires+1秒まで待つ。初期トンネルは stop と期限を照合する
open_managed_tunnel を使い、TLS 接続も同じ stop を渡す。中継本体は認可期限で
両方向を停止する。Host 以外は従来どおり8秒。

実ソケットの対照で、認可期限後かつ回収猶予内に、中継が EOF/reset となり、
新規 CONNECT が上流 socket を作らないことを確認した。非Hostの serve_fixture
自体も実行して、8秒で受信待ちが終了することを確認した。通常lib109件成功。
修正後の実VM local TLSも全5ケース成功し、expiredでは署名期限前の子生存、
期限〜期限+1秒の間のpidfd signaled（子の実行不能）、gatewayと世代回収を確認した。
これらは平文relay/CONNECTの境界対照と実子の終了確認であり、remote TLS実経路の
証拠は引き続き次段階で取得する。

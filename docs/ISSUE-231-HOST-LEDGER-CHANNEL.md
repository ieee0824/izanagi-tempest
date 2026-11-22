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
公開鍵・要求・期限・独立に指定した台帳 ID を検証する。実 SQLite、管理登録、
supervisor の接続を含む試験へ拡張する必要がある。

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
現在、この経路の実 supervisor を使った VM 間の回収試験は未完了。

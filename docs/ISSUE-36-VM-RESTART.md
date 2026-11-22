# #36 ログイン VM の vsock 付き再起動手順と結果

2026-11-22、ownerの任意時刻での再起動とログイン以外の準備委任（#18284/#18285）に基づき実施した。
実ログインは未実施。以下の手順と末尾の実行結果を分けて参照する。

## 確認済み状態（2026-11-22 UTC）

- VM: tempest-login-test、ユーザー tempest。旧 QEMU PID 558909、QMP running、ディスク I/O 正常。
- SSH: ホスト loopback 127.0.0.1:22333。owner はこれまでと同じ踏み台経路を使う。
- 旧ディスク: /dev/shm/tempest-133-vm.6XgXuE0Z/ubuntu-24.04-minimal-cloudimg-amd64.img。
- 旧 seed: 同ディレクトリの seed.img。既知ホスト鍵は known_hosts に保持。
- 管理用一時鍵 tempest-36-prelogin-admin は 20261122100958Z に失効済み。
  期限更新前の管理接続は publickey 拒否を確認。owner 自身の既存鍵は変更しない。
- ホストディスク拡張後の空きは約49 GB。/dev/shm は別枠で空き約346 MB。

## 配備準備済みの成果物

マージSHA 4245d9c1a829922adf4ef93694c3766b274c8298 から release/locked/offline で入口をbuildした。
入口は3631736 bytes、SHA256は
f687897685483c780577ae0caaeac58658469c0b8c310342d9bf02b8df0b0a30。
旧b52d363成果物にはCLIのvsock拒否がないため配備せず、旧manifestもsupersededへ更新した。
root0555でホストに準備済みだが、新入口のguest配置・認可/relayサービス起動はまだ行っていない。
同じSHAのbroker一式とroot0600のartifact記録も準備した。

専用userの実KVM証拠は[最小VM実測](LINUX_KVM_ARTIFACT.md)と
[管理者gate](LINUX_KVM_ADMIN_GATE.md)に記録されている。今回も実UID/GID/groupと
両deviceのread/write権限を照合済み。これは今回のVM起動や認証成功の代わりにはしない。

## 切断前に揃えるもの

1. coder が #232/#234 のマージ SHA と #36 最終配置チェックを確認する。
2. owner が接続中の VM で、一時管理鍵だけを新しい短い期限へ更新する。
   公開鍵はホストの既存 prelogin-key と照合し、from=10.0.2.2 と restrict を維持する。
   秘密鍵はホスト外へ出さない。更新後に管理側が BatchMode/StrictHostKeyChecking で接続確認する。
3. 初回はownerが任意時刻の再起動を承認済み。準備操作はpronniaへ委任されている。
   VMのhostname、既存host key、復帰するSSH portを照合する。
4. 管理側が guest の sync と通常の shutdown を実施する。強制 kill を通常手順にしない。
   QMP 状態と旧 PID の終了を確認してからディスクを操作する。

## 停止後のホスト作業

VMが停止したことを確認してから、root管理ディレクトリを作り、旧ディスクとseedを
疎ファイルとしてコピーする。元ディスクは復帰確認まで保持する。

```sh
sudo install -d -o root -g tempest-kvm -m 0750 /var/lib/tempest-manual-login-vm
sudo install -d -o root -g tempest-kvm -m 0750 /var/lib/tempest-manual-login-vm/inputs
sudo install -d -o tempest-kvm -g tempest-kvm -m 0700 /var/lib/tempest-manual-login-vm/tempest-login-test
sudo cp --sparse=always /dev/shm/tempest-133-vm.6XgXuE0Z/ubuntu-24.04-minimal-cloudimg-amd64.img /var/lib/tempest-manual-login-vm/tempest-login-test/root.qcow2
sudo cp /dev/shm/tempest-133-vm.6XgXuE0Z/seed.img /var/lib/tempest-manual-login-vm/inputs/seed.img
sudo chown tempest-kvm:tempest-kvm /var/lib/tempest-manual-login-vm/tempest-login-test/root.qcow2
sudo chmod 0600 /var/lib/tempest-manual-login-vm/tempest-login-test/root.qcow2
sudo chown root:tempest-kvm /var/lib/tempest-manual-login-vm/inputs/seed.img
sudo chmod 0440 /var/lib/tempest-manual-login-vm/inputs/seed.img
sudo cmp /dev/shm/tempest-133-vm.6XgXuE0Z/ubuntu-24.04-minimal-cloudimg-amd64.img /var/lib/tempest-manual-login-vm/tempest-login-test/root.qcow2
sudo qemu-img check /var/lib/tempest-manual-login-vm/tempest-login-test/root.qcow2
```

## 新しい起動構成

旧構成のマシン、CPU、seed、NICとSSH転送を維持し、メモリを試験済みの1536 MiBへ増やす。
専用非ログインユーザーtempest-kvm（UID999/GID988、supplementary kvm=993）で実行する。
既存の/dev/kvmと/dev/vhost-vsockはroot:kvm 0660で、このユーザーだけに必要な既存group権限を使う。
新たなユーザー作成やdevice権限の拡大は行わない。KVM失敗時は停止し、root/TCGへfallbackしない。
旧 QEMU と同時起動しない。CID231とTCP22333の未使用も起動前に確認する。

```sh
sudo systemd-run --unit=tempest-manual-login-vm-36 \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=NoNewPrivileges=yes --property=Restart=no \
  -- /usr/bin/qemu-system-x86_64 -machine q35,accel=kvm -cpu max -smp 2 -m 1536 \
  -nodefaults -display none -monitor none \
  -serial file:/var/lib/tempest-manual-login-vm/tempest-login-test/serial.log \
  -drive file=/var/lib/tempest-manual-login-vm/tempest-login-test/root.qcow2,if=virtio,format=qcow2 \
  -drive file=/var/lib/tempest-manual-login-vm/inputs/seed.img,if=virtio,format=raw,readonly=on \
  -netdev user,id=private,restrict=on,hostfwd=tcp:127.0.0.1:22333-:22 \
  -device virtio-net-pci,netdev=private \
  -device vhost-vsock-pci,id=ledger,guest-cid=231 \
  -qmp unix:/var/lib/tempest-manual-login-vm/tempest-login-test/qmp.sock,server=on,wait=off
```

これは閉じた準備構成で、外向き通信を有効にするコマンドではない。旧登録は使わず、
新しいQEMU PID/start ticks/QMP socket/実CIDと新boot識別子をroot管理登録へ反映する。
PIDはsystemdのMainPIDと照合する。/proc/PID/statusで実/実効/保存UID/GIDが専用userと
一致すること、QMPのSO_PEERCRED PID/UIDがMainPID/999であること、query-statusがrunning、
qom-getのledger guest-cidが231であることを確認する。brokerは登録PID/start ticks、
QMP peer PID、生存pidfd、実デバイスCIDを各要求で照合する。root0600の登録をguestへ渡さない。
QMP socket・disk・runtime directoryはtempest-kvm所有の0700/0600内とし、root brokerが照合する。
seedはroot所有inputs 0750配下のroot:tempest-kvm 0440とし、専用userによる変更・置換を防ぐ。

## 復帰と配置の確認

- 管理側とownerが同じSSH経路で再接続し、保存した既知ホスト鍵、hostname、ユーザーを照合する。
- guestのvsockモジュールとhost CID2:23100への管理チャネルを確認する。
- マージSHAの入口digest、固定CLI/bundle/BusyBox、root設定、CAと公開鍵、target/permit/generation、
  host台帳と独立承認の期限、brokerサービス、子/通信/世代の回収を最終チェックへ記録する。
- guestには署名秘密鍵やホスト台帳原本を置かない。ownerの直接指示により管理SSH鍵は維持する。
  当該鍵だけexpiryを外し、from=10.0.2.2/restrictを残した。秘密鍵はhost root内、他のowner鍵は変更しない。
- 通信候補 platform.claude.com:443 のIPは現在の管理原本と再照合し、通信時間枠の判断を受ける。
  08:17 UTCの候補記録だけでは外向き通信の実施判断にならない。
- restrict=onのVMから承認先への実通信経路は別途具体化が必要。広い制限解除をこの手順に含めない。
- 外向き通信と単回手動認証の実施条件が揃うまで、ownerにauth loginを指示しない。

## 復帰できない場合

新しい起動を停止し、保存した旧ディスク・seedと互換のハードウェア構成で復帰を試みる。
復旧時も専用tempest-kvm user/KVM固定を維持し、root QEMUやTCGへfallbackしない。
その条件で復帰できない場合は停止したままownerへ状況を報告する。
同じディスクを複数のQEMUから同時に開かない。ホスト鍵不一致時は記録を確認し、
known_hostsを無条件に消さない。ownerには再接続状況と復帰先を案内する。


## 実行結果（2026-11-22）

- 旧guestでsync/systemctl poweroffを行い、旧QEMU PID558909の終了を確認してからコピーした。
- disk/seedはcmp一致、qemu-img checkはエラーなし。旧入力は復旧用に保持している。
- systemd tempest-manual-login-vm-36.serviceで起動。InvocationID c4e787face2d4ce08a624afc41546c9d。
- PID792457/start ticks68804771、全UID999/GID988、kvm group993、NoNewPrivs=1。
- QMP SO_PEERCREDは同じPID/UID/GID。running、query-kvm enabled、ledger guest-cid=231。
- guest boot ID b2905502-e641-4a7a-b83e-834f151f5f9c、hostname tempest-login-test、user tempest。
- 既存hostkeyとStrictHostKeyCheckingを維持してSSH/sudo復帰。root内へ同じknown_hostsも保存した。
- guestのvsock driverを確認し、固定dummy bytesのguest→host実接続をCID231で照合した。
  初回の待受けは15秒でtimeoutしたため、同一orchestrator内でlisten→SSH probeを直列化して再実行し成功した。
- restrict=onと従来のNIC/SSH22333を維持。guestのrouteは10.0.2.0/24のみでdefault routeなし。
- root0600のlive-instance draftに新boot/PID/QMP/CIDを記録し、merged require_live_instanceで照合した。
  認可の発行・消費、外部接続、Claude loginは行っていない。
- 管理SSH鍵はownerの直接指示で維持し、再接続でも検証済み。ownerがVM準備を操作する前提は外した。

次はB案設計レビュー後のローカルrelay実装とdummy検証、その後の最新入口/relay配置である。

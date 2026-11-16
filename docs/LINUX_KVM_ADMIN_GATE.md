# KVM専用system userの管理者checkpoint

2026-11-16のread-only確認: x86_64、`/dev/kvm`はroot:kvm 0660、char 10:232、
kvm groupはgid993でmemberなし。ubuntu(uid1000)はkvm非所属です。
`tempest-kvm` user/groupは未作成です。この文書のコマンドは未実行です。

## 管理者が行う専用user作成

実行前に同名user/groupがないことを再確認し、存在した場合は既存設定を監査して中止します。
root管理者が次を実行します。作業者ubuntuのgroupやsudoers、device modeは変更しません。

```sh
getent passwd tempest-kvm
getent group tempest-kvm
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --groups kvm tempest-kvm
getent passwd tempest-kvm
id tempest-kvm
sudo passwd --status tempest-kvm
stat -c '%a %U %G %t:%T' /dev/kvm
id ubuntu
```

受入条件はsystem UID、login不可shell、home未作成、password locked、
追加groupはkvmのみ、ubuntuはkvm非所属、deviceはroot:kvm 0660の維持です。
自動rollbackやuser削除は行いません。

## 段階1: 専用userのopen/API version

次は固定deviceのopenとKVM_GET_API_VERSIONだけです。VMは作成しません。
Pythonを使うのは管理者が明示実行する診断に限定します。

```sh
sudo -u tempest-kvm /usr/bin/env -i /usr/bin/python3 -c 'import os,fcntl,json; fd=os.open("/dev/kvm",os.O_RDWR|os.O_CLOEXEC); version=fcntl.ioctl(fd,0xAE00,0); os.close(fd); print(json.dumps({"api_version":version,"passed":version==12})); raise SystemExit(0 if version==12 else 1)'
```

受入は専用userでopen成功・API version12・FD閉鎖・exit0です。
API version成功を必要ioctl、VM起動、Izanagi成功へ拡張しません。

## 段階2以降の未完条件

必要extension列挙とioctl、KVM_CREATE_VM、固定最小vCPU/guest memory、
KVM_RUNの決められたexit、全FD/child/resource回収を順に独立gateとします。
これらの固定検証binaryは未実装なので、管理者向け実行commandはまだ提示できません。
任意VM/image/command入力を受けない検証器をレビューし、root所有・非書換えpathへinstall、
binary hashを固定してから専用userで実行する段階です。

固定Izanagi最小起動はその後です。既存aarch64 imageの流用を成功根拠にせず、
x86_64 build manifestとimage hash、network制約、owner/firewall/doas/mailbox、
control/clock/timeoutを再実測します。全段階のexit/固定診断/回収証拠が揃うまでKVM gateは未達です。

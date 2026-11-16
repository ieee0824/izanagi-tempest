# KVM専用system userの管理者checkpoint

2026-11-16のread-only確認: x86_64、`/dev/kvm`はroot:kvm 0660、char 10:232、
kvm groupはgid993でmemberなし。ubuntu(uid1000)はkvm非所属です。
`tempest-kvm` user/groupは未作成です。この文書のコマンドは未実行です。

## 管理者が行う専用user作成

実行前に同名user/groupがないことを再確認し、存在した場合は既存設定を監査して中止します。
root管理者が次を実行します。作業者ubuntuのgroupやsudoers、device modeは変更しません。

```sh
set -eu
if getent passwd tempest-kvm; then
  echo 'tempest-kvm user already exists; stop for review' >&2
  exit 1
else
  lookup_status=$?
  test "$lookup_status" -eq 2
fi
if getent group tempest-kvm; then
  echo 'tempest-kvm group already exists; stop for review' >&2
  exit 1
else
  lookup_status=$?
  test "$lookup_status" -eq 2
fi
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --groups kvm tempest-kvm
getent passwd tempest-kvm
id tempest-kvm
sudo passwd --status tempest-kvm
stat -c '%a %U %G %t:%T' /dev/kvm
id ubuntu
```

`getent`の「対象なし」(exit 2)だけを作成前の期待結果とし、既存entryやlookup失敗なら
useraddへ進みません。以降も各コマンドの失敗で中止します。

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
固定検証binary `tempest-kvm-probe` は実装・build-only検証済みで、device実行は未実施です。
`623b34b`のnative Linux/x86_64 debug binary SHA256は
`d6c746bd13d8b219eb11086d83d50ee03b38a90989179cd6c5563f69ef6089e3`です。
専用identity照合、VM/vCPU/RAM、固定IO→HLT、親5秒deadline、PIDFD回収、
primary/cleanup別診断を実装しています。unitはKVMを開かず、実hardware gateは未達です。
test backendでのstage別failure injectionは追加済みです。[artifact報告](LINUX_KVM_ARTIFACT.md)の
範囲と残件を監査してから管理者向け実行commandを確定します。
任意VM/image/command入力を受けない検証器をレビューし、root所有・非書換えpathへinstall、
配置後も同じbinary hashを再確認してから専用userで実行する段階です。

固定Izanagi最小起動はその後です。既存aarch64 imageの流用を成功根拠にせず、
x86_64 build manifestとimage hash、network制約、owner/firewall/doas/mailbox、
control/clock/timeoutを再実測します。全段階のexit/固定診断/回収証拠が揃うまでKVM gateは未達です。

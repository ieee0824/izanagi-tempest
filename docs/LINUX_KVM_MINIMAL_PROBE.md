# 固定x86_64最小KVM検証器案

未実装の設計案です。[管理者checkpoint](LINUX_KVM_ADMIN_GATE.md)のstage2用で、
Izanagi/image/network/credentialは扱いません。
APIの根拠は[Linux公式KVM API](https://docs.kernel.org/virt/kvm/api.html)です。

## 入力と主体

独立Rust binary、引数なし、固定`/dev/kvm`のみopenします。任意image、guest bytes、
command、path、環境設定を受けません。x86_64以外とroot実行を拒否し、
管理者が作ったtempest-kvmの実UID/GIDとsupplementary groupを照合します。
ユーザー作成・device permission・sudoers変更は検証器に実装しません。

## 固定実行列

1. API version12、KVM_CHECK_EXTENSIONでUSER_MEMORY、NR_MEMSLOTS>=1、
   IMMEDIATE_EXITを要求します。SET_TSS_ADDRも確認し、未対応は固定診断で失敗します。
2. KVM_CREATE_VM(type0)。Intel用TSS領域は固定0xfffbd000に設定しguest RAMと重ねません。
3. 匿名private RAMを固定2MiB mmapし、slot0/GPA0へSET_USER_MEMORY_REGION。
   disk、NIC、irqchip、外部deviceは作成しません。
4. vCPU0を1個作成し、GET_VCPU_MMAP_SIZEを検査してkvm_runを共有mapします。
5. GET_SREGSで初期状態を読み、real modeのCS base/selector=0、CR0.PE=0を固定。
   SET_SREGS/SET_REGSでRIP=0x1000、RFLAGS=2、RSP=0x2000を設定します。
6. GPA0x1000に固定命令`b0 2a e6 e9 f4`を置きます
   （AL=0x2a、port0xe9へ1byte OUT、HLT）。
7. KVM_RUNの最初のexitはIO/OUT、port0xe9、size1、count1、data0x2aのみ受理。
   data_offsetとsizeはmap内境界をoverflow検査してから読みます。
8. 再度KVM_RUNしてHLTのみ受理し、GET_REGSでAL=0x2aとRIPを確認します。
   想定外exit、shutdown、internal error、余分なIO、繰返し上限超過は失敗です。

CPU/host差で上記列が成立しない場合も成功へfallbackしません。
SREGS/TSS/extensionの具体ABI layoutは実装時に固定header由来の型とsizeテストで再確認します。

## 期限と回収

監視parentが専用childを作り、childだけがKVM FD/VM/vCPUを生成します。
生成後fork/dup/SCM_RIGHTSは行いません。全FDはCLOEXEC、実行childはexecしません。
parentはPIDFDとbirth/lineageへ結合し、monotonic全体5秒を上限にします。
期限時はchildをPIDFDでkillし、terminal wait/reapまで成功を返しません。
通常終了と協調的な失敗ではkvm_run unmap、vCPU close、memory slot削除、VM close、RAM unmap、
KVM closeを明示し、`explicit_cleanup_complete`として記録します。cleanup失敗は本処理成功を覆します。
SIGKILL期限経路ではこの明示cleanupは実行不能なのでfalseとし、親がPIDFD死亡とterminal reapを確認した
`child_terminal_reaped`を別checkにします。最後のFD参照消滅によるkernel回収を、
明示unmap/slot削除成功へ読み替えません。期限は常に失敗で、回収成功でも上書きしません。
公開診断は固定stage/check/errno番号/exit/signalと回収boolだけで、guest memoryは出力しません。

## 配布・受入

管理者はレビュー済みcommitをlocked buildし、SHA256を記録してroot所有0700 directory内の
root所有0755固定binaryへinstallします。配布時にはdirectoryをroot:tempest-kvm 0750、
binaryをroot:tempest-kvm 0550へ固定し、専用userの通過・実行可能性と書換え不能を
全ancestorで検査します。build staging用0700 directoryを配布先として流用しません。
最終install path/hashはartifact作成後に固定し、placeholder commandは実行させません。

受入には正常IO→HLT、unsupported extension、異常exit、deadline、cleanup失敗の負例、
全FD/child回収、再実行時残留なしを含めます。これが成立してから固定Izanagi起動へ進みます。

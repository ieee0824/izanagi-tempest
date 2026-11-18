# 最小bootstrapのhost package変更見積り

2026-11-18、以下のsimulationを実行しexit 0を確認しました。

```sh
apt-get --simulate --no-install-recommends install qemu-system-x86=1:8.2.2+ds-0ubuntu1.18 qemu-utils=1:8.2.2+ds-0ubuntu1.18 musl-tools
```

結果は0 upgraded、24 newly installed、0 remove、12 not upgradedでした。
既存libc/loader/libgccなどの更新はこの解決結果に含まれません。
新規libraryとsystem data/firmwareの追加はあります。実行前には再simulationし、
この一覧との一致、各packageの取得・hash、依存closureを確認します。
APT indexが変わった場合に最新版へ自動置換せず、計画を更新します。

| 追加package | version |
| --- | --- |
| acl | 2.3.2-1build1.1 |
| ipxe-qemu | 1.21.1+git-20220113.fbbdc3926-0ubuntu2 |
| libasound2-data | 1.2.11-1ubuntu0.3 |
| libasound2t64 | 1.2.11-1ubuntu0.3 |
| libbrlapi0.8 | 6.6-4ubuntu5 |
| libpcsclite1 | 2.0.3-1build1 |
| libcacard0 | 1:2.8.0-3build4 |
| libdaxctl1 | 77-2ubuntu2 |
| libndctl6 | 77-2ubuntu2 |
| libpixman-1-0 | 0.42.2-1build1 |
| libpmem1 | 1.13.1-1.1ubuntu2 |
| librdmacm1t64 | 50.0-2ubuntu0.2 |
| libslirp0 | 4.7.0-1ubuntu3.1 |
| liburing2 | 2.5-1build1 |
| libusbredirparser1t64 | 0.13.0-2.1build1 |
| qemu-system-common | 1:8.2.2+ds-0ubuntu1.18 |
| qemu-system-data | 1:8.2.2+ds-0ubuntu1.18 |
| libfdt1 | 1.7.0-2build1 |
| seabios | 1.16.3-2 |
| qemu-system-x86 | 1:8.2.2+ds-0ubuntu1.18 |
| qemu-utils | 1:8.2.2+ds-0ubuntu1.18 |
| musl | 1.2.4-2 |
| musl-dev | 1.2.4-2 |
| musl-tools | 1.2.4-2 |

Packer/pluginはこのAPT変更には含みません。
[全体計画](LINUX_IZANAGI_BOOT_PLAN.md)の固定入力照合と分けて扱います。

## 導入結果（2026-11-18）

room #16345の指示後、全24件を各version指定、no-install-recommends、no-upgrade、
no-removeで再simulationし、追加24・更新0・削除0と全version一致を確認しました。
全debを取得し、APT indexのSHA256と実体hashを照合しました。
[取得物のversion/hash一覧](LINUX_BOOTSTRAP_PACKAGES.json)に記録しています。
同じ24件の固定version導入はexit0、dpkg-queryの最終versionも全件一致しました。

`/usr/bin/qemu-system-x86_64`と`/usr/bin/qemu-img`は8.2.2
（Debian 1:8.2.2+ds-0ubuntu1.18）を返しました。binary SHA256はそれぞれ
`8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854`、
`634320b91165669917123e8e79cce1c4d00cee0a4aa4d662d7c0a8186479b3fb`です。
`/usr/bin/musl-gcc`も配置されました。version確認のみでVMは起動していません。

導入前後のloader/libc/libgcc SHA256は[依存監査](LINUX_KVM_DEPENDENCIES.md)の値と同じです。
ubuntuはkvm非所属、tempest-kvmはUID999/GID988、groups988+993、
`/dev/kvm`はroot:kvm0660 char10:232を維持しています。

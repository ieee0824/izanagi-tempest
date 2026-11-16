# 専用hostのKVM検証器依存・配置監査

2026-11-16、取込みcommit `2a7cce8`（`dfe9573`のtest修正を含む）でread-only収集しました。
専用Linuxで12test(serial)とworkspace全target clippy成功。binary SHA256は
`d6c746bd13d8b219eb11086d83d50ee03b38a90989179cd6c5563f69ef6089e3`で不変です。
検証器本体、device、install、user作成は実行していません。

## 直接依存とNSS追加候補

readelfのinterpreterは`/lib64/ld-linux-x86-64.so.2`、NEEDEDはlibgcc_s.so.1、libc.so.6、
ld-linux-x86-64.so.2です。RPATH/RUNPATHはありません。
空環境のloader `--list`で下記解決を確認しました。本体のentryは実行していません。

| 実体（/usr/lib/x86_64-linux-gnu/配下） | SHA256 | mode |
| --- | --- | --- |
| ld-linux-x86-64.so.2 | 5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f | 0755 |
| libgcc_s.so.1 | d93224d2b0dab4247598be683adca02f5cf00586f99c187579cd7e92058fb7cb | 0644 |
| libc.so.6 | 755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a | 0755 |
| libnss_systemd.so.2 | 3d6ce4ca24d0001182accbe820df2f3fb9f4eb8035356ce6f214c966805bf5eb | 0644 |
| libcap.so.2.66 | 6ac6abc86ac891c6e13486470e26f1d939f47fda9e6b5d5508a7f5ec881adc84 | 0644 |
| libm.so.6 | 5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a | 0644 |

全実体とsymlinkはroot:root所有、解決先までのdirectoryはroot:root 0755でした。
symlinkの0777表示はtargetの書換え権ではなく、link置換は親directory権限で制御されます。
`/etc/ld.so.cache`、ld.so.conf、nsswitch.conf、passwd、groupはroot:root 0644、
ld.so.conf.dとそのancestorはroot:root 0755、設定3fileはroot:root 0644です。
`/etc/ld.so.preload`は不在でした。

NSS設定はpasswd/groupとも`files systemd`です。libnss_systemdは直接NEEDEDに出ない追加候補で、
そのNEEDEDはlibcap/libm/libc/loader、libcapはlibc、libmはlibc/loaderでした。
systemd NSSもloader --listで解決先を確認しましたが、実user lookup時のdlopenやIPCを観測した証拠ではありません。
従って表は静的/loader解決closureであり、全実行時依存の網羅を主張しません。

## 固定配置コマンド案（未実行）

[専用user checkpoint](LINUX_KVM_ADMIN_GATE.md)が完了し、管理者が上記hash/closureを再検証してから実施します。
既存destinationがあれば上書きせず中止します。現在このコマンドへの実行移行はしていません。

```sh
set -eu
getent passwd tempest-kvm
getent group tempest-kvm
namei -l /var/lib
test ! -e /var/lib/tempest-kvm-probe
test ! -L /var/lib/tempest-kvm-probe
test "$(sha256sum /home/ubuntu/izanagi-tempest/target/debug/tempest-kvm-probe | cut -d ' ' -f 1)" = d6c746bd13d8b219eb11086d83d50ee03b38a90989179cd6c5563f69ef6089e3
sudo install -d -o root -g tempest-kvm -m 0750 /var/lib/tempest-kvm-probe
sudo install -o root -g tempest-kvm -m 0550 /home/ubuntu/izanagi-tempest/target/debug/tempest-kvm-probe /var/lib/tempest-kvm-probe/probe
sudo sha256sum /var/lib/tempest-kvm-probe/probe
test "$(sudo sha256sum /var/lib/tempest-kvm-probe/probe | cut -d ' ' -f 1)" = d6c746bd13d8b219eb11086d83d50ee03b38a90989179cd6c5563f69ef6089e3
sudo namei -l /var/lib/tempest-kvm-probe/probe
sudo -u tempest-kvm test -x /var/lib/tempest-kvm-probe/probe
sudo -u tempest-kvm test ! -w /var/lib/tempest-kvm-probe
sudo -u tempest-kvm test ! -w /var/lib/tempest-kvm-probe/probe
```

各コマンドは失敗時に中止し、sourceとinstalledの両hashが上記固定値に一致するまでdevice実行しません。
workspace sourceがinstall中に変わってもinstalled hash不一致で拒否します。
installは実device実行の承認と分け、まだ`sudo -u ... probe`は実行しません。

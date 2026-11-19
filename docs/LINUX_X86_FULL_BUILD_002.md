# Linux x86 full image build002: 自動 speech 起動と入力先を観測

room #16496 の監査後、[計画](LINUX_X86_FULL_BUILD_002_PLAN.md)を一度実行した。full image build は未成功。固定26入力/権限、serial/debug/output不在、新unit未使用、uid999残留なし、3port空、旧001全証拠不変を直前確認した。

observer17379を先行し、caller35184を開始。Invocationは `1f448e03bef84112a502ac4f7997c7a6`、unit/cgroupは `tempest-izanagi-bootstrap-image-002.service`。実QEMU280220のcwdとunit WorkingDirectoryは `/var/lib/tempest-izanagi-full-build-002/work` に一致。serial/debugは通常file0600で、127.0.0.1限定のHTTP/SSH/VNCを観測した。

## 前後の画面と ISO 設定

boot入力前のread-only framebuffer PNGは640x480、SHA `343dfd0e87462438fa71c5e92c3d8436bc4fc814bb754d1122b6ad01ad1ffadd`。BIOS installer menuでGraphical installが選択され、画面下部に speech synthesis を7秒後に開始する表示があった。Packerはその時まだboot_wait 60s内にいた。

入力後PNGは1280x800、SHA `81afd2d0df8a3ca50506bca91b8f3d293ddec00fa91004f0cf0739713e7da22a`。Starting speech synthesis、sound card検出失敗、Press enter to continue anywayが表示され、その下にPackerの `^[/install.amd/vmlinuz console=tty0 console=ttyS0,115200n8 auto=tru` という入力途中の文字列が見えた。こちらからキー入力は送っていない。

[include先設定の選別記録](LINUX_X86_ISOLINUX_DIRECTIVES.json)で、menu.cfgがincludeするspkgtk.cfgは `timeout 300` と `ontimeout /install.amd/vmlinuz vga=788 initrd=/install.amd/gtk/initrd.gz speakup.synth=soft --- quiet` を持つ。SHAは `189e399eaee5a30acda5995b2becbb01332798bea1da401bf5a46da29cfc556f`。親isolinux.cfgのtimeout0だけでは実効timeoutを説明できなかった。

002では、30秒の自動speech起動がPackerの60秒待機より先に発生し、Packerのboot commandがboot promptではない入力画面へ送られたことを前後の観測と設定から確認した。001には入力前画面がなく、同一原因という説明は002証拠に基づく推定と区別する。

serialは0bytesで実kernel cmdlineは未取得。private debugにpreseed GETの一致行はないが、GET未発生やauto引数不存在の証明にはしない。debug全体をroom/modelへ出さず、private原本のhashを保存した。

## 中止と回収

無人進行不能のため、同Invocationを再確認し002unitだけsystemctl stopした。手動入力、別retry、旧001再起動はない。caller35184のexec sessionは143、serviceはログ/observerでexit1、observer17379はexit0。callerの戻り値とservice終了値を区別する。service runtime1min57.116s、Packer reported1min56s。

[結果JSON](LINUX_X86_FULL_BUILD_002_RESULT.json)に127observations、同Invocationのloaded/failed終端、trusted PID1/UID0 journal、全private証拠/partialのhashを保存。独立確認でcgroup消失/uid999なし/3ports閉、追加kill不要。全26入力SHAと旧001snapshot/証拠SHAは不変。

partial imageと全ログ/前後PNGは保全。lockdown/provision/実guest ABI/load/境界は未到達。新image boot/認証/livecallは未実行。次はboot_waitとISOの自動起動期限の整合を修正して別入力・別attemptで監査する。

## 時系列の選別照合

[時刻記録](LINUX_X86_FULL_BUILD_002_TIMING.json)へprivate debugの選別eventとobserver/PNG保存mtimeを保存した。debugはQEMU実行12:09:29、boot wait12:09:31、Typing boot commands12:10:31。observerのQEMU初観測は12:09:30.158479 UTC、入力前PNG保存は12:09:54.576453 UTC（画面はspeech開始まで7秒）、入力後PNG保存は12:10:48.579309 UTC。PNG時刻は保存mtimeでありフレーム取得瞬間の厳密な時刻ではないが、入力前画面のcountdown期限よりPacker入力開始が遅いことと整合する。serialの実kernel cmdline欠測は変更しない。

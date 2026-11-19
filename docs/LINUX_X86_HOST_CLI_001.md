# Linux x86 host CLI build001

正式 runtime の mock 検査に向けた build-only。
[正確なargv/env/source/tool/lock/ELF/依存/容量](LINUX_X86_HOST_CLI_001_RESULT.json) と
[実行 helper](evidence/host-cli-build-001/build.py) を保存した。

clean source revision 8ddf75fd2bb174939597ce7669e1902e4bb3a10f を git archive で新private sourceへ固定した。
既存 stable cargo/rustc1.100.0 の絶対path、既存private Cargo cache、新HOME/target、明示envを使用した。
release / locked / package tempest / x86_64-unknown-linux-gnu / jobs2、1800秒上限。
caller56264は同handleで終端exit0。Cargo buildは77秒だった。
source全fileとCargo.lockは前後不変。追加featureは指定していない。

binary は10738144 bytes、SHA256 4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f。
ELF64 little-endian x86-64 PIE、GNU loader。
ldd は libgcc_s/libm/libc/loader を解決し missing library はなかった。
空き容量は44239605760から43909705728 bytes。
VM実行、image/core/global設定変更、model/実credentialは使用していない。

次は正常mock2回/reset、seed適用後応答喪失、finding/retest4presenceを具体計画に分ける。
正常runtimeはprimary/retestの複数VMを逐次起動するため、単一QEMU identity固定のsmoke observerを流用して合格にしない。
固定host CLIと各run/sessionの対応、同時台数/制限/回収を検査するobserver条件を別途監査する。
HTTP sidecar、外部positive control等の未証明gateは維持する。

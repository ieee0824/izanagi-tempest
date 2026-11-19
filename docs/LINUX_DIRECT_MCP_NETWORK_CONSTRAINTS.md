# Linux direct MCP childの通信制約実装メモ

#36の[固定VM経路案](LINUX_DIRECT_B_VM_ROUTE_PLAN.md)の実装レビュー補足。2026-11-19にLinux公式仕様を確認した。hostへのpolicy load、VM、認証、API実行の証拠ではない。

## syscallと宛先の責務

[Linux seccomp仕様](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)ではfilterはsyscall番号・引数値を評価し、pointer先をdereferenceしない。したがってconnectのsockaddr pointer値だけを比較して127.0.0.1:固定portへの制限を実装したとは扱えない。

[LinuxのBPF attach type表](https://www.kernel.org/doc/html/latest/bpf/libbpf/program_types.html)はcgroup/connect4、connect6、UDP sendmsg、egress等を別hookとして列挙している。connect4を接続したという結果だけを全family・全送信経路の制限へ拡張しない。

この経路の実装案では次を組み合わせる。

- A/Bは既存のsocket/connect拒否を維持し、親発行pipeだけを使う。
- trusted MCP childのsocket生成は必要なIPv4 TCP clientに限定し、IPv6/UDP/raw/AF_UNIX等とbind/listen/acceptを許可しない。固定binaryの実際の必要syscallを確認してからpolicyへ反映する。
- MCP child専用cgroupで接続先IPv4 addressとportを当該VMの値へ限定する。connect hookだけで十分かは、既存socketの継承、send系syscall、socket optionと実binaryの挙動も含めて検査する。
- attach前に未制約socketを作らせない。起動FD closureにnetwork socketがないこと、policy有効化とcgroup加入後にのみReadyを開くことを照合する。
- child/descendantのcgroup移動、program detach/置換、policy書換えを子の権限から拒否する。必要なkernel機能・権限・attachの独立観測が欠ければ起動拒否する。

port制限はVM identityとは別である。同じportのreceiver置換は、QEMU PID/starttime/cgroup/socket所有、session fingerprint、既存の認証Readyで拒否する必要がある。固定argv/envもfilesystemやegressのOS強制の代わりにはしない。

## 実装・実測へ引き継ぐ項目

固定hostのkernel/config/cgroupv2/tool/library metadataを先に保存する。BPF対応とロード成功・attach先の実identity・その後の有効性を区別する。root以外のchildへ権限を残さず、ロード失敗時にhost制限解除や別backendへ自動fallbackしない。

正例は固定VMとの認証済み接続、負例は別run port、hostの別port、非loopback、IPv6/UDP/raw/Unixと継承socket。receiverの前後正例と追加accept数を保存し、拒否errnoだけで受信側の稼働を推定しない。FDとmount/config探索の境界、異常時の期限・全group回収は別に照合する。

本メモは公式hook/APIの存在を確認したものに限る。選択hostでのkernel対応、実program、完全なsyscall closure、attach検証、実MCPの正負通信は未実装・未実測である。

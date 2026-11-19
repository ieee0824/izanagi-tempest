# Linux x86 full image build001: 言語選択待ちで中止

room #16475 の監査後、[固定計画](LINUX_X86_FULL_BUILD_001_PLAN.md) の command を一度実行した。実 full image build は未成功。

直前に 26 input hash/mode/owner、新 output 不在、unit 未使用、uid999 process 不在、固定 ports 空き、free60683649024 bytes を再確認。observer session40739 を先行し、caller session13618 を開始した。unit は `tempest-izanagi-bootstrap-image-001.service`、Invocation `39a30e58b71649d88535100b4e964880`、cgroup は同名の system.slice 直下。

ISO 照合後 QEMU CD boot、Packer VNC boot command 入力、SSH 待ちに進んだ。SSH 待ち中の read-only VNC framebuffer 取得で Debian installer の言語一覧と `Prompt: '?' for help, default=20>` を確認した。VNC は framebuffer request のみでキー入力・clipboard は送っていない。private PNG の SHA は `4ad9f54834caafbb5f79e605c0f4f2583b5e92005f2c2fca99f0bab648537c40`。

この状態では無人インストールが進まないため、対象 unit の Invocation を再確認して `systemctl stop` した。手動 installer 入力、fallback、再試行は行っていない。kernel/installer が起動したことと、preseed が無人適用できたことを区別する。auto/priority/url 引数が guest に実際どう渡ったかは未観測で、原因は確定していない。

caller13618 は exit1（Build cancelled）、service runtime 3min10.114s。observer40739 は exit0、同 Invocation の loaded/failed、ExecMainCode1/ExecMainStatus1、cgroup_pids 空の終端を取得した。PID1/UID0 の journal 終端も別に採取した。

[結果と証拠 hash](LINUX_X86_FULL_BUILD_001_RESULT.json) に、198 observations、全区間 external listener false、最終 unit 属性、trusted journal、private log/PNG/partial image の SHA を保存した。独立確認で cgroup 消失、uid999 process 不在、HTTP18082/SSH22222/VNC5902 全閉を確認。追加 kill は不要だった。全26 input hash は不変。

partial qcow2 は196672 bytes、SHA `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133`。これは完成 image ではなく保全対象の失敗 artifact。lock-down/verify/provision 到達と実 guest ABI/load/境界の証拠はない。生成 image の boot、credential、livecall は未実行。

次は固定 BIOS boot command と installer auto/preseed 条件を調査する。旧 snapshot、work、証拠は保持し、修正時は別定義・別 snapshot・別 attempt として監査する。

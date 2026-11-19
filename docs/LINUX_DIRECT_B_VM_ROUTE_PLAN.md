# #36 Linux Bの当該run固定VM経路案

room16910に基づく設計レビュー用。追加secret、fresh login、subscription/live API call、実装、新VMは行っていない。既存A/B/G dummy隔離からBの当該run VM経路だけを結線する次段階を定義する。dummy成功から本番CLI起動許可を推定しない。

## 現コードの境界と不足

- `crates/tempest-linux-probe/src/lib.rs` はdummy調査専用で、Tempest runtimeへの依存もLaunchPermit生成APIもない。`runtime.rs::baseline` はA/B/Guardへ固定IPC FDを渡すだけで、BからIzanagi MCPへ接続するdata pathはない。
- `capsule.rs::enter` は独立mount/PID/net namespace、固定library snapshotとprivate workを構成する。`seccomp.rs` はsocket/connect/mount/traceを拒否し、A/Bのrecvmsgによる遅延FD受領も許可しない。この既存負例を緩めない。
- `vm.rs` はrun-private workspace/HMAC、up supervisor、boot nonce/session fingerprint、非autostarting管理MCPを束縛する。これはhost orchestrationであり、Linux B capsule内からの到達を実測したものではない。
- `proxy_cli.rs` の汎用 `-- UPSTREAM [ARGS...]` は任意command/cwdを受けるhost側入口で、Bへそのまま公開しない。`relay.rs` の有限frame/queue/budget/drainを再利用候補にするが、RPC drainをguest子孫終了へ昇格しない。
- `run_cli.rs::verify_production_mcp_catalog` はIzanagi binary/version/OS/archとcatalogを検査する既存経路。これとLinux dummyのOS隔離は未結線。既存 `adapter.rs::CliAdapter::new` はLaunchPermit検証とDarwin sandbox contractを前提とし、Linux direct launcherではない。
- `direct_evidence.rs` とDIRECT_PROFILE_SCHEMAのdirect investigationはrequest単位観測をUnobservedとする別型で、既存relay proof/LaunchPermitへの変換を認めない。

## 提案するdata path

```text
A dummy tool client --固定stdio/pipe--> B capsule内のbounded RPC gate
  --起動前に親が渡した専用pipe FDだけ-->
trusted run-local Izanagi MCP process --既存認証済みsession--> 当該run VM
  --> guestの既存exec/HTTP interface --> local dummy LWS

trusted harness: VM作成/Ready/seed/seal/export/down、private key、owner binding
G: pidfd/cgroup/FD identityと期限/回収の監視（credentialやRPC本文は受け取らない）
```

BはUID62002、空net namespace・socket/connect拒否を維持する。TCP/UNIX listenerを新設せず、起動前に作ったdirection固定pipeだけを受ける。Bがread/write可能なFD番号・direction・pipe inode・peer process identityをReady contractに含め、close_except後に再照合する。A/B間FDとB/upstream間FDは別物で、Aへupstream FDを渡さない。遅延SCM_RIGHTS、任意socket/path、別processへのFD譲渡を許可しない。

Izanagi MCPはtrusted harnessが固定binary/argv/cwd/最小envで起動するrun-local childとし、private workspace/HMACはそのprocessだけが利用する。B capsuleにkey/secret-file/config/session.json/host run directoryをmountせず、BへHMAC FDを継承しない。subscription OAuthはこの経路の入力に存在しない。汎用proxy CLIからchildを選ぶのではなく、親が作ったopaqueなroute bindingだけを消費する専用入口を設ける案とする。

MCP childをB capsule外に置くため、このchildはtrusted computing baseとして明記する。Bのnet制約がchildへ自動的に及ぶとは扱わず、childは固定workspace以外を選べないargv/env、既存非autostarting session操作、per-requestのsession lifetime再照合で拘束する。childのhost egress/設定探索が残るなら未達として止め、B隔離の証明で代用しない。

## Bindingと許可・拒否

route bindingは親発行run nonce、VM boot nonce、supervisor PID/starttime、session fingerprint、Izanagi/QEMU/Tempest/image/guest/bridge/gate executableの実SHA、workspace owner identity、MCP catalog digest/schema/version/OS/arch、各FD identity、A/B/G pidfd/cgroupを含める。任意path文字列だけをroute authorityにせず、親が開いたFDとNOFOLLOW/root非write snapshotのidentityを使う。run間で再利用しない。起動直前・Ready後・RPC開始前に生存とbindingを確認し、変更/欠測/不確定は閉鎖する。

許可するのはreview済み実catalogのtools/list/initializeと、当該run policyが選んだtool/schemaに合うRPCのみ。catalogを推測・名前だけ照合・未知methodを透過しない。management用claim/seed/seal/export/up/downやrun selectionをA/Bのtool surfaceへ追加しない。予算・有限frame/queue/IO/drain deadline・request ID対応をhostとB gateで固定し、catalog drift/duplicate/oversize/foreign responseを拒否する。MCP budgetはprovider request budgetを証明しない。

| 攻撃・誤接続 | 要求する拒否/観測 |
|---|---|
| 別run/別nonce/古いReady・session/別VM | dispatch前拒否、別VM counter増分0。正例counterでreceiver稼働も確認 |
| path/symlink/binary/library置換、PID再利用 | fd/pidfd/starttime/digest再照合で拒否。TOCTOU未対処のまま起動しない |
| host endpoint、10.0.2.2、別port/Host、Internet | A/B socket禁止、guestは既存restrict/firewall。独立receiver前後対照と追加accept0。全Internet拒否と単一port結果を混同しない |
| credential/config/session/通常HOME/親proc-fd-env | A/B/Gの既存dummy canary正負対照、Bからprivate HMAC path/FD/VM管理directoryへ非到達。raw secretを診断へ出さない |
| FD注入・peer置換・任意upstream command | 既存ancillary負例維持、pipe/peer/cgroup照合、汎用CLI引数からの選択を禁止 |
| RPC滞留、child EOF/crash、応答不確定、budget超過 | admission閉鎖→有限drain→guest freeze/子孫確認→export→down→group回収。未確定writeを新ID再送しない |

## 固定source/binary/catalogと実行前gate

設計の検査対象sourceはlinux-probeのcapsule/contract/runtime/seccomp/worker/registry、Tempestのvm/guest_transport/proxy_cli/relay/run_cli/capability_proof/direct_evidence、Izanagi MCP serverとそのHTTP tool schema。実装後にsource revision/全closure SHA・new clean build argv/env/tool/lock・binary ELF/loader・実catalogを固定する。現在のdummy binaryを新結線binaryだったと再ラベルしない。

既存実測host4f66/imageb46a/guest3bc9はVM側baseline候補としてprovenanceを保持するが、新B/gateを含むsource/binaryはまだ存在しない。catalogは同じ固定Izanagi executableから別processでread-only initialize/tools/listを取得し、そのrunの実MCP childでも同catalogを再確認する。実source/catalog不一致は起動拒否。既存imageのmetadataや失敗結果は後付け変更しない。

実行前はsource/設計レビュー→純粋validator/負例→clean build→固定artifact/owner-mode/FD closure→UID/KVM/容量/unused root-unit/output確認→明示的に範囲を定めたdummy VM実測の順とする。管理者が承認済みのKVM/専用UID契約を維持し、root QEMU/TCG/権限緩和へfallbackしない。既存のhardlink物理例外は追補へ束縛する。

## LaunchPermitと段階受入

最初の結線検査はdummy専用の新fixtureで、Aもdummy、credentialもcanary、LWSもdummyだけ。結果は `production_authorized=false`/formal対象外を維持する。内部のopaque route bindingはFD/sessionの所有証明であり、LaunchPermitではない。

本番CLIの起動は既存LaunchPermit/即時closure検証を通る必要がある。現Darwin relay profileやLinux direct investigation reportを偽装・変換せず、Linux direct用のproduction capability/backendが正式に設計・実装・受入されるまでproduction adapterは拒否を維持する。probe結果がtrueだからpermit不要、あるいはrun_cliのnative分岐を直接呼ぶ、という迂回は設けない。fresh login/実subscription call/反復比較は別段階で、今回の案・既存dummy承認から実行しない。

実測受入は、同runのexec/HTTP→LWS正常経路とHTTP/API/PCAP/control intent、上表の別run/host/credential/egress負例、catalog/FD/session/binary入替拒否、異常時閉鎖と全group回収、連続2runのbinding/state独立性を必要とする。全対象についてcaller/observer同handle終端、同Invocation trusted終了、UID/cgroup/port/FD/mount/root cleanupを独立保存する。GCunknown/receipt false/欠測は成功に補完しない。proofが不十分なら本番起動を許可せず残gateとして報告する。

[読取専用source baselineと既存artifact SHA](LINUX_DIRECT_B_VM_ROUTE_SOURCE_001.json)を保存した。新結線binaryとそのproduction catalogは未作成・未測定である。本案は[DESIGN](DESIGN.md)の薄い外部連携方針と[IMPLEMENTATION](IMPLEMENTATION.md)のMCP予算・管理/agent経路分離を維持する将来案であり、既存direct調査の受入範囲を変更しない。

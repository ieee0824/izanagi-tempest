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

## room16913レビュー後の内部契約と残実装

最初のsource差分は `tempest-linux-probe/src/route_contract.rs` の内部・未結線prototypeである。`ParentPipe`は親がOwnedFdで両endを保持し、実fstatのFIFO/device/inodeとF_GETFLのread/write方向を確認する。これはsocketのpeer credentialではない。`verify_holders`は親が取得する全holderのPID/starttime/cgroup inode・FD番号・directionの集合を比較し、unknown・extra dup FD・欠測・PID再利用を拒否する。ただし実host全holder scannerは未実装であり、B/G内の局所観測をその代用にしない。test内のsynthetic holder集合は実process唯一性の証拠ではない。

`Gate`はrun/VM/session/executable/catalog/supervisor binding、固定dummy catalogのentry/schema/digest、有限call/frame/絶対期限、単一inflight、正整数IDの非再使用、応答対応と異常応答後の閉鎖を検査する。schemaはdummy用の限定subsetで、実Izanagi production catalog compilerではない。initialize/tools/listやVM接続の実transportも未結線。専用fixture接続点 `connect_fixture` は常に `OsIsolationUnavailable` を返す。この型・負例成功からVMを起動する入口はない。既存run()/worker()/seccompとLaunchPermit経路は変更していない。

### Trusted MCP childのOS強制案（未実装）

固定Izanagi sourceの `session.rs::SessionBackend::connect_agent` と `agent_session.rs::connect` はQEMU sessionのhost_portに対する127.0.0.1 TCP接続と認証Readyを使う。したがって、空net namespaceに移すだけではこの正例が成立しない。Unix socketに接続する実装だったとは扱わない。

候補はMCP child専用cgroupにrootが固定cgroup-BPF connect4/egress制約を接続し、検証済み当該QEMUの127.0.0.1:host_port TCPだけを許可すること。IPv6/UDP/raw/AF_UNIX等の別socket family/typeとsocket FDの継承・遅延注入を別seccomp/FD closureで拒否し、他host port・10.0.2.2・外部・別run portへの正負対照を行う。Bはこれと独立にsocket/connect拒否を維持する。cgroup programと読取専用policyのhash/link/attach先inode・継承/移動禁止・child pidfd/全descendantを再検証し、backend対応/attach/検証が欠ければ起動前拒否する。現環境でBPF利用可・この制約が成立すると測定したわけではない。

同portのreceiver差替えはport filterだけでは排除できないので、QEMU PID/starttime/cgroup/socket所有とsession fingerprintを照合し、既存per-run認証Readyでも拒否を確認する。port許可をVM identity証明にしない。

childのfilesystemは別mount capsuleに固定executable/loader/libs、当該sessionの必要fileとdummy HMACだけを親FDから公開する。通常HOME、他run、設定/認証探索先、汎用host rootやproc/fdを公開しない。何が必要fileかは実固定MCPで測定してclosureへ含め、argv/envからの任意path追加を認めない。hostネットワークを残すTCBなので、net制約・mount・caps/seccomp・pidfd/cgroupの全てがVM実測前の必須gateである。現在のprototypeはこのbackendを持たず必ず停止する。

### 次の実装一覧

1. privileged全holder scannerの有限走査・dup/fork/消滅時Unknown・同時性/寿命拘束と、B/G局所観測の別report。
2. child専用cgroup-BPF/FD closure/mount/権限dropを実装し、固定session以外のhost/別run/egress拒否と正例を独立観測する。
3. real catalog/schemaのreview済み変換、bounded MCP handshake/transport、既存relay admission/drainとVM session lifetimeを統合する。
4. source/OS契約のレビュー後にclean artifact buildと明示的なdummy VM試験。連続2run/異常回収/情報非露出を保存する。
5. Linux direct production capability/proof/backendとLaunchPermit接続は別の設計・受入。owner-private config/login/session/cleanupとsubscription egress、fresh login/live callの許可、#7/#8/#36全体gateは未達のまま。

### 固定バイナリの最初の結線（room #17034）

入口は固定 Izanagi の `mcp` サブコマンドとする。固定 source の
`src/main.rs::run_with` は通常の設定読み込みより前に
`commands::cmd_mcp` へ分岐し、実装は stdin/stdout の改行区切り JSON-RPC
と stdin EOF による終了を使う。最初の結線ではローカルの固定 dummy caller
から `initialize` と `tools/list` だけを送る。既存 VM session は当該 run
との binding に固定する。この二つのフレームで VM agent への接続成功は判定しない。
実 catalog は照合用にのみ扱う。現在の `Gate` は `dummy_exec` と
`dummy_http` 専用なので、実 catalog を通すために許可条件を緩めない。

- 監督プロセスが `route_contract::ParentPipe` でデータ用の二本を生成する。
  MCP child が要求の読み端を stdin、応答の書き端を stdout に割り当て、
  B が逆側の二端を持つ。stderr は監督側へ分離する。子は既存
  `os::close_except` で不要端を閉じてから、事前継承した制御 FD で通知する。
  監督側も対象の四端を閉じる。遅延 FD 受け渡しは行わない。
- 監督プロセスは元 pidfd と starttime を保持し、二子を別 role に配置する。
  `Group::inspect_while_frozen` に期待 role 集合、二本の pipe と四端の期待配置、
  親の残存端ゼロを渡す。解凍確認成功後のみ B のデータ送信を解放する。
  exec 前に止める場合は exec 後の FD 配置も照合するまで B を解放しない。
- EOF と元 pidfd の終了を有限期限で確認し、異常時は `Group::kill` 後に
  子を回収して `Group::cleanup` を行う。監督の異常終了に対しては、
  connect4 fixture で確認済みの上位 subreaper の所有順序を移植候補とする。
  B の既存 seccomp は維持する。MCP child の session 専用 connect4 制約と
  mount/権限境界は別 role に実装し、C fixture での実測をその実装の証跡に流用しない。

room #17037 の解放条件は、同じ元 pidfd/starttime を保持したまま、
exec 後の固定ファイルの device/inode、MCP 側の stdin/stdout の方向と
対象 pipe、B 側の対応端、親残存端ゼロを確認することとする。
`identity::Process::identity` と既存 `runtime.rs` の期待実行ファイル照合を
再利用候補とする。確認と解凍が完了するまで、B の制御 gate は閉じて
要求をゼロに保つ。固定フレームの応答照合に続いて B が書端を閉じ、
MCP stdout EOF と両子の回収を独立に確認する。
`supervisor.rs::session_cli` の drain 記録は参考にするが、
任意 upstream argv を受ける入口はこの固定結線に接続しない。

room #17053 の固定 artifact 検査は `route_contract::FixedMcpArtifact` に置く。
固定 SHA を照合する対象は `os::Snapshot::trusted` が sealed memfd に
コピーしたバイト列とする。exec に渡す FD と exec 後の実体照合に使う
device/inode は、同じ sealed snapshot から取得する。レビュー対象のビルド出力は /tmp 配下にあるため、
起動時の入力は root 所有で書込制限した
`/usr/local/libexec/tempest/izanagi-mcp-fixture` を予定する。
このパスは staging 先の契約であり、配置と loader/library closure の確認は
実行前に行う。artifact 検査からプロセスを起動する入口はまだない。

固定 ELF を起動せず `readelf -lW` と `readelf -dW` で確認した。
PT_INTERP は `/lib64/ld-linux-x86-64.so.2`、DT_NEEDED は
libgcc_s、libm、libc と同 loader の4件で、RPATH/RUNPATH は存在しない。
4件の依存も同集合内に収まる。`fixed_mcp_libraries` は既存 capsule の
配置表を再利用し、このホストで採取した各ファイルの SHA-256 に
sealed snapshot を照合する。実 mount と loader の起動確認は後続とする。

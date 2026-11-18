# Linux x86 image smoke001 の固定入力と単発計画

room #16520/#16526 に対応する可逆準備。[full image build003](LINUX_X86_FULL_BUILD_003.md) の生成物を使用する。新imageのbootはまだ行っていない。この具体入力とcommandのレビュー後に一度実行する計画。

## 入力と依存の固定

root `/var/lib/tempest-izanagi-image-smoke-001-v2`、unit `tempest-izanagi-image-smoke-001.service` を新設用に予約した。生成image SHA `5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e` と固定host CLI SHA `088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8` を新inputsへコピーした。build-inputs.jsonはfull003の実manifestからbyte-identicalでコピーし、guest metadataの期待値を維持する。

[全1304入力のfile hash/mode/owner、symlink target、directoryと外部runtimeのSHA](LINUX_X86_IMAGE_SMOKE_SNAPSHOT_001_V2.json)を保存。[専用userでの実検証](LINUX_X86_IMAGE_SMOKE_PREPARATION_001_V2.json)を参照。root:tempest-kvm、directory0750、通常file0440/executable0550。venvのsymlinkは固定inputs内またはroot所有/usr/bin/python3.12に限定し、リンク先のglobal binaryをchmodしない。uid999で全入力readable/nonwritableを確認した。

固定wheelhouseとhash付きrequirementsからroot専用venvを新規生成しoffline installした。Python -I -B/env-i、root snapshotのprefix、cryptography50.0.2/cffi2.1.1/pycparser3.12、AES-GCM dummy roundtripをuid999で確認。pip/global Pythonの更新や追加APTは行っていない。元の成功venv/全wheelと旧full001002003入力・証拠は不変更。全64 Python testsは成功。guest内実artifact inventory用commandも既知ELFの正例と不正headerの負例で確認した。

work/home、work/tmp、work/evidenceはuid999 private0700、work/outputは未作成。host mapped-xattrのset/getを専用userの一時fileで検査してから同fileを削除した。scriptは新output内に独立random transport HMAC file0600を生成し、ambient secretを使用しない。まだdummy transport鍵は作成していない。runtime原本をprivateに保持し、鍵値/鍵単体hash/raw summaryやguest argv全体を公開しない。

## 既存smokeへの限定差分

Izanagi/LWS core sourceとguest imageは変更しない。host smokeは新root repo配置から実行する。

- guest image metadataのarchitecture/ISO（入力にある場合）、agent/HTTP/eBPFの実SHAとELF machineを固定入力と照合する。kernel/libc/package/lddも取得し、missing libraryを拒否する。sidecar binaryのhash/依存確認はsidecar実起動の証明ではない。
- 独立random128bit nonceを含む `/tmp/tempest-trace-<nonce>` をguest PythonでO_EXCL作成し、同VM応答の実PID/pathを保存する。hostが期待したpathとの一致を確認し、終了後のevents.logおよび.1〜.3から当該PID/pathのopen/openat eventを検査する。probeのコードや期待値からeventsを生成する経路はない。
- 空log/別PID/別run path/類似prefix/exec引数だけではtrace合格にしない。fixtureはparserの検査のみで実採取の代用ではない。生event引数を公開せず、該当数と証拠file hashを保存する。log rotationも保存・private marker検査対象に含める。

## 実行順と固定command（未実行）

直前に全hash/mode/owner/外部runtime SHA、work/output・exit-status・caller/observer log不在非symlink、unit未使用、uid999残留なし、既存image003と旧証拠不変、空き容量を再確認する。private work/home/tmp/evidenceとruntime envを照合し、ambient AWS/Izanagi credentialsを引き継がない。

rootのread-only observerを先行する。

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/repo/integration/image_smoke_observe.py \
  --output /tmp/tempest-image-smoke-observation-001.jsonl
```

observerは固定unit/cgroup/Invocationと初回QEMU PID+process starttimeを保持し、観測identityの交代・PID再利用・identity不正/欠測・VM未観測terminalを拒否する。単一QEMU、user restrict=on、127.0.0.1の動的agent forward、固定base imageのsnapshot=on、固定workspace mapped-xattr/readonly=onを検査する。0QEMUの初期状態をpositive runtime証拠にせず、複数VM/制限緩和/非loopbackは失敗。raw fw_cfg/全argvは採取しない。観測失敗時はこのunitだけstop/必要時killし、別runへ移行しない。

以下を新private `/tmp/tempest-image-smoke-001.log` へumask0077/noclobberで記録する。newimageの実bootを含むため、まだ実行していない。

```sh
sudo -n /usr/bin/systemd-run --unit=tempest-izanagi-image-smoke-001 --wait --pipe \
  --property=Type=exec --property=User=tempest-kvm --property=Group=tempest-kvm \
  --property=SupplementaryGroups=kvm --property=KillMode=control-group \
  --property=RuntimeMaxSec=1800s --property=TimeoutStopSec=10s \
  --property=SendSIGKILL=yes --property=Restart=no --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=Delegate=no \
  --property='ExecStopPost=/usr/bin/python3 -I -B /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/record_exit.py' \
  --working-directory=/var/lib/tempest-izanagi-image-smoke-001-v2/work \
  /usr/bin/env -i PATH=/usr/bin:/bin TZ=UTC LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  HOME=/var/lib/tempest-izanagi-image-smoke-001-v2/work/home \
  TMPDIR=/var/lib/tempest-izanagi-image-smoke-001-v2/work/tmp \
  /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/python/bin/python -I -B \
  /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/repo/integration/image_smoke.py \
  --izanagi /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/izanagi \
  --image /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/image.qcow2 \
  --build-inputs /var/lib/tempest-izanagi-image-smoke-001-v2/inputs/build-inputs.json \
  --output /var/lib/tempest-izanagi-image-smoke-001-v2/work/output
```

ExecStopPostは既存の実測済みrecorderを固定unit/outputへ導出し、同Invocation/終了値の選別snapshotを新work/evidence/exit-status.jsonへO_EXCL/NOFOLLOW/fsyncで保存する。deactivating snapshotと最終terminal/cgroup回収は区別する。caller handleの終端とunitの状態を混同しない。GCでobserverがunknownになった場合はそのまま残し、trusted PID1/UID0/currentboot journal、exit recorder、script private結果、実成果物を別に照合する。

## 初回が検査する範囲と残るgate

初回は既存M3のowner/mapped-xattr/readonly/private mailbox/doas/fw_cfg/proc/cgroup/firewall、dummy local LWSの200/403/501、既知IDの反復・並行ciphertext取得、親normal/timeout/abnormal時の子の私有境界、export cgroup barrier、2つのdummy HTTP GETのAPI/PCAP境界を検査する。固定sourceのup成功はTraceStarted ack必須だが、raw ackを採取したとは呼ばず、追加nonce/PID/path eventで実採取の正証拠を別に要求する。

初回は `--tempest` とdelivery-race fixtureを指定しないため、独立Rust MCP route/forced delivery-raceは未測定。Izanagi HTTP sidecarのStartBehavior実起動/採取、外部到達拒否と正常positive controlの組、二run reset/cross-run contamination、全route coverage、正式モデル比較・実credentialは後続gateに残す。M3 HTTP/PCAPをIzanagi sidecarの証明に混ぜず、1PID/path traceを全syscall/ABI/時計精度の保証にしない。実AWSは利用しない。

## 終了と失敗

正常時もVM down後にcgroup/uid999/QEMU/動的host forward回収、base imageと全input/旧証拠不変を独立確認する。summaryのcollected_requires_reviewは正式受入ではない。private summary/API/PCAP/eventsと全logを保持し、公開するのは選別check結果/件数/hash。独立dummy transport鍵は結果・回収を照合後に値や単体hashを出さず削除を記録する。

失敗/期限超過/観測不確実は同unitだけ停止回収し、部分証拠と失敗原因を保全する。tracer無効化、dummy event注入、手動root設定、別retry、旧image修正で合格にしない。追加package/core修正が必要なら実行せず候補を報告する。

## 準備時点の確認

[review専用unit定義](../integration/tempest-izanagi-image-smoke-001.service)をsystemd-analyze verify --man=noで検査しexit0。hostへunitをinstall/enable/startしていない。実行は上記のtransient単発commandで行う計画。root snapshotへの配置とoffline venv installのsetup logはprivate rootに保持する。全input closureは1304 entries、root venvの新prefixと専用userでのimport/crypto/--help検証まで完了。

準備時のunitはnot-found/inactive、専用uid999 processなし。空き容量は約52.2GBで、直前値は実行前に再採取する。

## v2再固定の理由と範囲

16531/16532の「同時1台でも逐次別VMに交代できる」反例を09b91beで修正し、cba819dでROOTをv2へ固定した。sourceはPID stat field22をcmdline読取前後で照合し、observer process内でPID+starttimeを保持する。host bootIDは準備記録と最終trusted journalで別に束縛する。1秒sample間に完結して一度も見えなかったprocessの不存在や全lifetime完全監査を保証するものではない。

未実行の初回trial001に対するinput snapshot version2であり、2回目のVM起動ではない。旧v1root `/var/lib/tempest-izanagi-image-smoke-001` と[全v1入力](LINUX_X86_IMAGE_SMOKE_SNAPSHOT_001.json)は不変更で保持し、v1 observerを実行しない。unit名は未使用の同じ001を使う。image/CLI/guest/core/wheel版本は同じで、新image build/追加packageはない。

v2全1304input・外部runtime SHA・全directory owner/mode、uid999 readable/nonwritable、private work、xattr、root venv prefix/import/AES/--helpを再検査。旧v1全input SHA/modeも不変。空file/別run nonce pathのtrace負例、逐次PID交代・同PID/starttime交代・未観測terminalのobserver負例を含む全64testsが成功した。現行command/service/期待image/share pathはすべてv2を指す。新output/key/exit evidenceは未作成で、実VMはまだ0回。

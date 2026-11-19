# Linux x86 sidecar001 固定準備計画

## 状態と担当

単発VMとcollector回収は完了。[結果](LINUX_X86_SIDECAR_001.md)を参照。以下は固定計画・実施前準備記録として保持する。

[sidecar設計案](LINUX_X86_SIDECAR_001_DESIGN.md)に基づく新試験。root /var/lib/tempest-izanagi-sidecar-001、unit tempest-izanagi-sidecar-001.service、observer profile sidecar-001。
runner/public receiver-client helper/pure evidence検査はcoder、PLAN/固定observer/caller/closure/回収はpronniaが担当する。
runner interface・結果受渡し・telemetry期待schemaのsource固定待ちで、root/snapshot/VMは未作成。
[proc003](LINUX_X86_PROC_EXPOSURE_003.md)までの原本・入力・鍵削除追補を保持する。#13の調査closeをsidecar受入成功へ読み替えない。

## 固定する境界

同full003 image、Izanagi16d0b559/LWS2c0ea463、固定host CLI/offline artifact reportと既存artifact/exec/trace/rotation検査を維持する。
restrict_network=true/read-only mapped share、guest fixture127.0.0.1:19090、proxy127.0.0.1:18080、baseline host127.0.0.1、mock classifier/allow_export=false。
実model/credential/AWS/外部receiverは使用しない。上流manualのrestrict=false/writable share手順は流用しない。
公開helperは秘密を含まない固定sourceだけをVM前に配置し、host xattr設定→host0444化の順とする。
個別guest statを実測しない場合はhost mappingとguest読取から一般化しない。

## 検査と証跡の条件

StartBehavior認証→TraceStartedとsidecar readinessをsource契約へ照合し、Ready/環境変数だけで成功としない。
receiver/clientは固定loopback endpointと有限期限/件数/bytesだけを扱い、workspace書込や任意targetのHTTP forwardを追加しない。
正例はreceiver側nonce/body/件数/bytesとclient固定responseを突合する。
負例は別loopback port/不許可Hostの拒否と正常receiver対照・未到着を組み合わせる。
sidecar固定PID/starttime/parent/UID/argv、offline HTTP artifact hash/ELFを別に記録する。actorのexe EACCESを実稼働exe hash測定成功へ変えない。
telemetryの期待variant/run/session/boot/source/時刻/件数/保存先と遅延上限を実装sourceから実行前に固定する。
writer unknown/abstainはそのまま保持し、転送成功を全writer attributionや分類精度へ拡張しない。
既存private exec/marker scanとevents/alerts/behavior rotation/up stdout/stderrを保全し、公開dummy bodyと秘密目印を区別する。
raw/秘密値はprivate、安全な集計・binding・判定scopeだけを公開する。

## 専用環境・開始と回収

専用UID999:GID988/kvm993、root/inputs0750・入力0440/実行0550・work0700、env-i/Python-I-Bと既存hash固定wheelのoffline venvを維持する。
interface確定後、必要なrunner/helper/observer/recorderと依存を新closureへ含め、source実bytes hashをroot作成前にassertする。
旧proc001/002/003・exec/presence/normal/seed-loss全tree/reservation/full/smoke証拠・旧鍵不在を照合する。
source/caller/service監査→snapshot/専用UID検査→実件数/tree/source/argv監査→直前不変/未使用unit/output/UIDなし/KVM/容量再確認の順で進む。
固定observerはimage_smoke_observe.py --attempt sidecar-001で専用unit/root/image/workspaceと単一QEMU identityを拘束する。
その後fixedcallerで1VM単発、暗黙retryなし。違反/失敗は当該unitだけ回収し部分証拠を保持する。
同handle終端、同Invocation exit recorder/trusted journal、cgroup/UID/port回収、全入力/旧証拠不変を別に保存しunknownを成功へ変えない。
当該dummy keyは結果監査後に正確path/lstatで別追補回収、値/単体hash非読取。旧raw/inputsを削除しない。
外部positive control・forced delivery race・全route/全期間・正式モデル比較は別gateのまま。

## 草案の検査

専用observerへ別image/share/cwd拒否とfixed unitの負例を追加する。caller/service/closureの具体argvはrunner interface共有後に確定する。
まだroot/snapshot/UID検査/caller/observer/VMは未実施。

## receiver/client interfaceの具体化待ち

room16737の固定source契約では、guestの単一exec内で有限期限のreceiver19090/19091をthread起動する。
19091への直接dummy転送成功を対照に、proxy経由19090成功、proxy経由19091失敗＋receiver件数増分0、非許可Host失敗を順に照合し、finallyでserver/threadを回収する案。
結果はprivate exec stdoutのbounded JSONとし、共有書込やbackground残留を使わない。
別loopback portの失敗はclient502/HttpRequest.policy=allowed/HttpOutcome=failed/status=null/upstream_bytes_written0であり、denied/403と記録しない。
非許可Hostはclient502/policy=denied/outcome=rejectedとして区別する。具体schema/遅延上限/固定argvは実装source共有後に確定する。

## 専用runner mode案

room16739に従い、--sidecar-evidenceと--exec-evidenceを組み合わせ、proc/tempest/forced-race同時指定は拒否する。
sidecarはExecへHTTP_PROXY/no_proxy空を注入するため、既存LWS/AWS CLI正常シナリオと混ぜない。
共通artifact/権限/read-only/bootstrap後、専用loopback fixtureだけを実行し、共通終了・保存・scanへ合流する。
既存artifact/trace検査は維持し、実行しないM3操作を今回の成功実績へ含めない。
追加closure予定はpublic sidecar_probe.py/proc_evidence.pyとhost pure sidecar_evidence.py。具体source/hashは実装監査後に固定する。
[caller草案](evidence/sidecar-001/run_once.py)と[service草案](../integration/tempest-izanagi-sidecar-001.service)は専用flagsを指定する。まだsource/依存未確定であり実行しない。

## source統合とclosure草案

PR60/11fde20をff6f884へ取り込み、Linux全136tests/skip0成功。旧通常M3ブロックと新elseの構文木完全一致、両mode共通の実trace probe、既存offline/artifact/read境界/rotation保持を確認した。
[snapshot作成草案](evidence/sidecar-001/prepare_snapshot.py)は修正smoke・proc core/paging・sidecar probe/evidenceの実bytes SHAをroot作成前にassertし、必須importをすべて含める。
旧proc003入力/RESULT参照file/鍵不在もroot作成前に照合し、旧001/002/exec等の保全検査を維持する。
[UID検査草案](evidence/sidecar-001/check_preparation.py)はstdinで渡し、固定help/importと権限/環境だけを確認する。helper main/host実procは実行しない。
sidecar identityの現在の実装はargv先頭の固定binary path、root UID、PID/starttime前後一致とppid値を保存する。全argvや親実体の直接同定を実測済みとは呼ばない。
telemetryは1fresh session/最大10MiB/32segment/50000record、fixture JSON最大16384B/exec timeout45秒に限定する。
caller/service/observerは準備済みだが、final source監査前にroot/snapshot/VMを作成しない。

PR60追補1f43e0bの終了health identity/audit保存検査を取り込んだ。Linux sidecar11testsのうち実socket fixture末尾の再bind検査がEADDRINUSEとなり、10成功/1error。
fixture転送・receiver件数・thread終了の検査後に発生し、TIME_WAITと残留listenerを区別する必要があるためcoderへroom16745で報告した。
先の136tests成功は追補前のsourceに対する結果として保持する。修正後の検査とfinal source監査前にroot/snapshot/VMを作成しない。

追補10563c4/bc14167を取り込み、TCP TIME_WAITと残留listenerを区別するconnect_ex拒否＋thread終了検査へ修正した。production Receiver設定は変更していない。
修正後はLinux全140tests/skip0成功（sidecar13件を含む）。先の再bind検査失敗は試行記録として残す。
sidecar probe/evidenceのproduction bytesは最終PR60と一致し、prepareの固定hashも整合する。まだroot/snapshot/VMは未作成。

## 固定準備結果

[1311入力snapshot](LINUX_X86_SIDECAR_SNAPSHOT_001.json)と[専用UID検査](LINUX_X86_SIDECAR_PREPARATION_001.json)を保存した。
source c1238a9、canonical tree2691eee579e28a4e71685534fa257ca287da20f8c0cfe93e6c4b0da326d06e22。
prepare90009/UID60602は同handle終端exit0。全hash/owner/mode/read可write不可・外部runtime・venv/AES/help/xattr/private work/newoutput/exit/log不在を確認した。
Linux全140tests/skip0とbootstrap13tests成功。help/importだけでhost helper main/実procは実行していない。
準備直前unit未使用/UID999なし/root未作成/free27783577600 bytesを確認し、準備時に旧proc001/002/003原本・鍵不在追補と旧exec/presence/normal/seed-loss全tree/reservation/full/smoke証拠不変を照合した。
実行直前も不変/未使用/容量/残留を再確認する。

先行observer予定:

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-sidecar-001/inputs/repo/integration/image_smoke_observe.py --attempt sidecar-001 --output /tmp/tempest-sidecar-observation-001.jsonl
```

続くfixedcallerは `python3 -I -B docs/evidence/sidecar-001/run_once.py`。
service/ExecStart一致・--exec-evidence --sidecar-evidence・offline artifact report指定を維持。現時点ではobserver/caller/VMは未実施。

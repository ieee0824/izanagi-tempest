# Linux x86 sidecar001 固定準備計画

## 状態と担当

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

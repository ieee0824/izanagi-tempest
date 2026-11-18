# Linux x86 host-endpoint001 対照付き接続拒否試験案

## 状態と対象

room16754/16756/16757の議論に基づく草案。room16763の最終interface指定に合わせ試験名・root/unit/profileをhost-endpoint-001とする。
root /var/lib/tempest-izanagi-host-endpoint-001、unit tempest-izanagi-host-endpoint-001.service。
まだrunner/helper/interface/具体上限は未確定であり、新root/snapshot/VMを作成しない。
sidecar001の限定loopback受入と混ぜず、通常M3や実model/credential/AWS/Internet receiverは使用しない。

## 固定境界

同full003 image/固定Izanagi16d0b559・LWS2c0ea463/CLIを維持し、restrict_network=true・snapshot・read-only mapped shareを変えない。
sidecar/HTTP proxyを通さず、guestはraw TCP socketで10.0.2.2:当該hostportへ直接接続する。
専用host receiverは127.0.0.1だけでbindし、試験の全区間で同一socket/portを保持する。0.0.0.0/外部bindや追加QEMU forwardは行わない。
port0で割り当てる場合、選ばれた正確portとsocket/owner/開始時刻をguest試行前に保存し、途中のclose/rebind/port再選択を認めない。
この結果は当該VM外host loopback endpointへの境界だけを示し、Internet全般や本番B通信を証明しない。

## 正負対照と判定

同じ公知nonceにphaseを付け、host-before/guest-attempt/host-afterとguest-loopback-controlを識別する。
host直接接続のbefore/afterは固定dummy body/返信/件数/bytesが一致することを要求する。
guest試行の前後でreceiver thread/socketが生存し同じportを保持することを確認する。receiverの停止・bind失敗・誤endpointを拒否成功に読み替えない。
guest側には別の有限loopback正常対照を置き、raw socket/APIとdummy送受信の実行成立を確認する。
guest→10.0.2.2:hostportは有限timeout付きで1回だけ実行し、実errno/timeout/接続成功/送受信有無を区別して保存する。
単なるHTTP拒否や解析失敗をネットワーク到達拒否へ変換しない。接続自体の成功は失敗として保持する。
receiverは前後2件の正規host対照だけを受信し、guest phaseの到着0と総件数/bytes不変を確認する。想定外接続/不正frame/予算超過も別に記録して失敗とする。
hostのmonotonic時刻でguest call開始終了を囲み、guestのclock値とhost clockを直接比較しない。

## 実装前に確定する契約

host receiverは新unit/cgroup内のcontroller配下で起動し、全体deadline・accept数・body/response/JSON bytes・thread join期限をsourceで有限にする。
guest helperは公知source/nonce/portのみを受け取り、任意targetや外部hostを指定できる入口を追加しない。
public helperはxattr設定→host0444化、guest read-only mappingを維持し、host上でhelper main/実procを実行しない。
具体mode flag・他modeとの排他・結果JSON schema・private保存先・純粋validatorの期待値をsource監査で固定してからcaller/service/closureへ反映する。
receiver途中停止・前後対照失敗・guest到達成功・誤nonce/phase/port・過大body・thread回収失敗等をsynthetic/host dummy fixtureで検査する。

## 固定・観測・回収

専用UID999:GID988/kvm993、root/inputs0750・入力0440/実行0550・work0700、env-i/Python-I-B、既存固定wheelのoffline venvを維持する。
source実bytes hashをroot作成前にassertし、必要な依存だけを新closureへ含める。
旧sidecar001/proc001/002/003/exec/presence/normal/seed-loss全tree/reservation/full/smoke証拠と鍵削除追補・不在を保持する。
source/具体argv監査→snapshot/UID検査→実件数/tree監査→直前不変/未使用unit/UIDなし/KVM/容量照合の順とする。
先行observerは専用unit/root/image/workspace、単一QEMU PID/starttimeとrestrict=on・hostloopback listenerを区別して観測する。
1VM単発、暗黙retryなし。失敗時は当該unitだけ回収し部分証拠を保持する。
同handle終端と同Invocation exit recorder/trusted journal、cgroup/UID/host receiver thread/観測port回収、全入力/旧証拠不変を別々に検証する。
observer GC等のunknownを成功へ変えない。raw/private markerは非公開、公開は対照counts/binding/errnoと限定scopeだけとする。

## 分担とaccept段階の判定

room16759に従いhost receiver/guest probe/pure validator/専用runner modeはcoder、PLAN/observer/caller/closureはpronniaが担当する。
receiverはpayload読取件数とは別にaccept総数を記録する。guestのTCP接続成立だけでも拒否試験は失敗とし、payload未送信を未到達へ変換しない。
host-before/host-after対照の2接続以外のacceptはfail-closeとする。未知nonce/phaseや途中EOFも予算内の明示的失敗として保持する。
observerはhost dummy listenerの正確endpoint/PID/starttime/socket所有と役割を記録し、QEMUのhostforward listenerとは別に照合する。
既存単一QEMU/restrict=on/storage/read-only/cwd/同Invocationの検査を緩めない。receiverの正確PID/socket実装契約を待ってprofileへ固定する。

## ready/ackによるreceiverの独立観測案

room16761/16762の案として、runnerは固定output/network-receiver.ready.jsonへschema/公開nonce/host_pid/127.0.0.1/port/socket_inodeをatomic0600で公開する。
observerは通常単link/999:988/0600・有限bytes/厳密schemaをO_NOFOLLOWで確認し、受信JSON内の任意pathを使用しない。
同unit MainPID/Invocation/currentboot/cgroupとPID stat前後starttime、fd socket inode、ss exact endpoint/PIDを独立照合する。QEMU listenerとは別roleで、port衝突・共有owner・identity変化を拒否する。
固定work/evidence/network-receiver-observed.jsonへroot:988/0440のackを排他的にatomic保存する。
pending0600でwrite/fsync→fchown/fchmod→link EXCL→pending削除/parent fsyncとし、既存ackを上書きしない。
runnerは有限10秒だけ正確nonce/pid/port/inode/Invocation/starttimeのroot-owned ackを待ち、未観測のままguest試行へ進めない。
ack後もreceiverの生存・identityを追跡し、終了後回収と区別する。ready公開時点・厳密field/最大bytes/starttime単位は実装interface共有後に確定する。

## room16763の固定interface

readyは共通bootstrap/readonly検査後、receiver bind/start直後・host-before対照より前に公開する。
最大4096B、厳密6fieldはschema_version=1、nonce=32hex、host_pid、address=127.0.0.1、port、socket_inode。
ackは同6fieldにhost_pid_starttime_ticks（/proc stat22のclock ticks）とinvocation_id=32hexだけを加えた8field、最大4096B/root:988/0440/通常単link。
runnerのack待機10秒、receiver全期限60秒/frame256B/accept5件目検出で停止、guest exec10秒/JSON16384B。
accept上限5は成功条件ではなく、前後対照2件以外の到着は依然失敗として保持する。
receiverはhost-after対照後にclose/joinし、共通trace等へ進む前にoutput/network-receiver.closed.jsonをatomic0600で公開する。
closedの厳密fieldはschema_version、identity=ready6field、receiver_closed=true、host_monotonic_ns。
observerはready→ack/live→closed/実listener不在を別phaseとして記録し、unit終了までreceiver生存を要求しない。
closed前のlistener消失、同port別owner、PID/starttime/socket identity変化は拒否する。
guest中の同bind/生存はrunner前後snapshotと独立ackに結び付け、samplingを全期間観測へ一般化しない。
ready/ack/closedの公開はlink EXCL/fsyncで上書きなしとし、trusted unit終了・cgroup回収とは別証拠にする。

## observer監査修正

room16768の指摘を受け、ready/closed読取後のfresh ss -H -ltnpeをport指定で取得し、unit外を含む全ownerとsocket inodeをFD inodeへ照合する。
bootstrapのunit内listener一覧だけをreceiver証明に流用しない。state再読一致と正規close→closed公開の最大1秒待機を行い、別owner/別inode/identity変化は即拒否する。
異常sampleは固定error metadataと共にflushしてから停止する。nlink2公開途中も同inodeの単link化だけ最大1秒待機する。
専用receiver10tests/既存observer24tests、Linux全163tests/skip0成功。実Linuxのpublic loopback socketでもfresh ssのPID/inode一致とclose後不在を確認した。
PR62の後続source追補（frame絶対期限・停止後counter）を取り込む前の結果として記録し、新root/snapshot/VMは未作成を維持する。

# Linux x86 proc-exposure001 計画

## 範囲と状態

草案、snapshot/VM未実施。旧exec-exposure001は変更せず、#13のactor可視/procを既存固定image上の新1VMで限定観測する。
root /var/lib/tempest-izanagi-proc-exposure-001、unit tempest-izanagi-proc-exposure-001.service。
Izanagi CLI SHA088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8、full003 image SHA5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7eを維持。
image/core/guest/Rust/global設定やpackageを変更せず、dummyのみで実model/credential/AWSは使わない。

## 観測と制限

image_smoke.py --exec-evidence --proc-evidence と image/proc_evidence.pyを使用する。
claim前・seed後・export前の3時点でactor UID1000からcmdline/environとFD一覧を採取する。
公知のargv/env canary、自身FD一覧をpositive controlとし、観測自身のPID/starttime前後一致を要求する。
他PIDについてもidentity前後/安定性、read/denied/vanished/errorと切詰めを区別する。
最大128PID、各blob8192bytes、JSON131072bytes。上限超過・切詰め・positive control不成立・予期しないerrorは完全な観測とせず失敗する。

rawはexec-evidenceのprivate streamへ入り、返却前/最終marker scan対象になる。公開は3時点の安全なcounts/controlsとexec集計/leak有無のみ。
collectorは保存scan/summaryとprivate metadata/count/modeを照合し、目印を回収して再scanしない場合は明記する。
FD内容、短命native process、native PIPE内部、PID切替の間隙、全期間/全routeの保証とはしない。
host timed_out=0ならtimeout部分出力はfixtureのみであり実測済みとしない。

## 固定・監視・回収

新root-owned read-only closureへCLI/image/manifest/offline report、smoke/proc/exec/trace/artifact/transport helper、observer/bootstrap/recorderを固定する。
proc helperはflag未指定時もimportされるため必須。既存hash固定wheelから新prefix venvをoffline構築する。
root/inputs0750、files0440/executable0550、UID999/Group988/kvm993 work0700、env-i/Python-I-Bを使用する。
全hash/mode/owner/外部runtime、UID read可write不可、venv/AES/xattr、新output/exit/log不在、未使用unit/UID/KVM/容量と旧証拠不変を確認する。

observerはimage_smoke_observe.py --attempt proc-exposure-001。
新unit/root/image/work/output/workspace、単一QEMU PID/starttime/cwd、snapshot/read-only mapped share/restrict usernet/loopbackを固定し、他root/image/VM置換を拒否する。
Typeexec/KillModecontrol-group/RuntimeMax1800/Stop10/Restartno/UMask0077/NNP/Delegate=no。
source/closure/command監査後に一度だけ起動し、違反/失敗/期限超過は当該unitだけ回収、部分証拠保持・暗黙retryなし。
caller/observer同handle終端、同Invocation exit recorder/trusted journal、cgroup/UID/port回収とinput/旧証拠不変を別に保存する。
GCはunknownのまま。dummy HMACは結果監査後に当該fileだけ値/hash非公開で削除する。

## 残るgate

旧exec001の173exec/346stream保存scanは別試験として保持する。
今回の3snapshotを全/proc監査や短命native/FD内容/実modelの証明へ拡張しない。
HTTP sidecar、外部positive control、forced delivery race、全route/正式比較は別gateのまま。

## 可逆準備の草案とguest guard待ち

[service](../integration/tempest-izanagi-proc-exposure-001.service)、[caller](evidence/proc-exposure-001/run_once.py)、[snapshot helper](evidence/proc-exposure-001/prepare_snapshot.py)、[UID検査](evidence/proc-exposure-001/check_preparation.py) を用意した。
--exec-evidence --proc-evidenceのExecStart一致/verifyとhelper構文を確認した。新proc helperはclosureへ明示追加した。
旧exec001の固定入力/選別結果と当該key削除追補の非存在確認も保全対象にした。
room16681に従い、actor UID1000だけでhost/guestを区別せず、root所有/etc/tempest/image.jsonの固定Izanagi/LWS manifestを確認するguest guardを待つ。
host上ではproc helperのmainや実/proc snapshotを呼ばず、synthetic fixtureだけで検査する。
現在のprepare/caller/observerは未実行。guard sourceとclosureの監査後にsnapshot作成へ進む。
